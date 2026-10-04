// mcp.go — `sy mcp`: stdio MCP server exposing the sy exec surface to
// agent harnesses (Pi, Claude Desktop, anything MCP-capable). Runs on
// the OPERATOR machine; dials managed hosts over SSH as the sy user.
//
// Deliberate power ceiling (§10): the three tools are exactly the
// unprivileged surface — run an argv, read host docs, read the policy.
// No approve, no listing of requests, no key management: approval
// stays a human act in an interactive root shell (`sysh approve`),
// never a tool call an agent could trigger on itself.
//
// Protocol: MCP over newline-delimited JSON-RPC 2.0 on stdin/stdout
// (initialize, tools/list, tools/call, ping). Exit 30 from a host
// (approval_required) is surfaced verbatim with the request id — the
// agent is told to stop and wait for the operator, never to chase it.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const mcpProtocol = "2025-06-18"

// --- JSON-RPC plumbing -------------------------------------------------

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// toolCallParams is the params of tools/call.
type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

func cmdMCP(args []string) {
	mcpServe(os.Stdin, os.Stdout)
}

// mcpServe is the loop; split out for tests.
func mcpServe(in io.Reader, rawOut io.Writer) {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(rawOut)
	defer out.Flush()

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var msg rpcMsg
		if err := json.Unmarshal([]byte(line), &msg); err != nil || msg.Method == "" {
			continue // not a request line
		}
		if len(msg.ID) == 0 || string(msg.ID) == "null" {
			continue // notification (initialized, cancelled, …) — nothing to answer
		}
		var result any
		var rerr *rpcError
		switch msg.Method {
		case "initialize":
			result = initResult()
		case "ping":
			result = struct{}{}
		case "tools/list":
			result = toolsListResult()
		case "tools/call":
			var p toolCallParams
			if err := json.Unmarshal(msg.Params, &p); err != nil {
				rerr = &rpcError{Code: -32602, Message: "bad tools/call params"}
				break
			}
			result = callTool(p.Name, p.Arguments)
		default:
			rerr = &rpcError{Code: -32601, Message: "method not found: " + msg.Method}
		}
		resp := rpcResp{JSONRPC: "2.0", ID: msg.ID, Result: result, Error: rerr}
		enc := json.NewEncoder(out)
		_ = enc.Encode(resp)
		out.Flush()
	}
}

func initResult() any {
	return map[string]any{
		"protocolVersion": mcpProtocol,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo": map[string]any{
			"name":    "sy",
			"version": version,
		},
	}
}

// --- tools --------------------------------------------------------------

// execFunc runs argv on a host; seam for tests.
var execFunc func(host string, argv []string) (execResult, error)

func defaultExecFunc(host string, argv []string) (execResult, error) {
	hf, err := loadHosts()
	if err != nil {
		return execResult{}, err
	}
	hc, err := hf.resolveHost(host)
	if err != nil {
		return execResult{}, err
	}
	return execSSH(hc, argv)
}

type toolDef struct {
	Name        string
	Description string
	InputSchema map[string]any
}

func toolsListResult() any {
	props := func(extra map[string]any) map[string]any {
		p := map[string]any{
			"argv": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "argv to execute; each arg printable ASCII without spaces",
			},
			"host": map[string]any{
				"type":        "string",
				"description": "host name from hosts.toml (default used if omitted)",
			},
		}
		for k, v := range extra {
			p[k] = v
		}
		return p
	}
	tools := []toolDef{
		{
			Name: "sy_exec",
			Description: "Execute one argv on a managed host as the unprivileged sy user, exactly like any other agent exec. The server-side policy decides what is allowed; argv is the unit of trust (no shell semantics). An approval-required outcome is returned as text with the request id — the operator must approve it in a root shell; do not retry.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": props(nil),
				"required":   []string{"argv"},
			},
		},
		{
			Name:        "sy_docs",
			Description: "List or read the operator-maintained host documents (sy-docs builtin): sy_docs with no name lists; sy_docs <name> reads one.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": props(map[string]any{
					"argv": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "the argv to send; typically [\"sy-docs\"] or [\"sy-docs\",\"name\"]",
					},
				}),
				"required": []string{"argv"},
			},
		},
		{
			Name:        "sy_policy",
			Description: "Return the current server-side policy of a host (sy-policy builtin).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": props(map[string]any{
					"argv": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "the argv to send; typically [\"sy-policy\"]",
					},
				}),
				"required": []string{"argv"},
			},
		},
	}
	items := make([]map[string]any, 0, len(tools))
	for _, td := range tools {
		items = append(items, map[string]any{
			"name":         td.Name,
			"description":  td.Description,
			"inputSchema":  td.InputSchema,
		})
	}
	return map[string]any{"tools": items}
}

// callTool dispatches one tools/call. Every outcome is a valid MCP
// tool result; failures are isError: true text, never exceptions.
func callTool(name string, args json.RawMessage) any {
	text, isErr := runTool(name, args)
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isErr,
	}
}

func runTool(name string, args json.RawMessage) (text string, isErr bool) {
	if execFunc == nil {
		execFunc = defaultExecFunc
	}
	var a struct {
		Host string   `json:"host"`
		Argv []string `json:"argv"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return "bad arguments: " + err.Error(), true
	}
	if name != "sy_exec" && name != "sy_docs" && name != "sy_policy" {
		return "unknown tool " + name, true
	}
	if name == "sy_docs" && !argvIsBuiltin(a.Argv, "sy-docs") {
		a.Argv = append([]string{"sy-docs"}, a.Argv...)
	}
	if name == "sy_policy" && !argvIsBuiltin(a.Argv, "sy-policy") {
		a.Argv = append([]string{"sy-policy"}, a.Argv...)
	}
	res, err := execFunc(a.Host, a.Argv)
	if err != nil {
		return err.Error(), true
	}

	// Approval-required (gateway exit 30): the host's stderr carries
	// the JSON result line; surface the request id and stop.
	if res.Exit == 30 {
		if rid := requestIDFromStderr(res.Stderr); rid != "" {
			return fmt.Sprintf("approval required (request %s): nothing ran. An operator must run `sysh approve %s` in a root shell on the host, or deny it; the request expires on its own if ignored. Do not retry this call until the operator answers.", rid, rid), false
		}
		return fmt.Sprintf("approval required; nothing ran (exit 30). %s", res.Stderr), false
	}

	out := res.Stdout
	if out == "" {
		out = res.Stderr
	}
	return fmt.Sprintf("exit %d\n%s", res.Exit, out), res.Exit != 0
}

// argvIsBuiltin reports whether argv already starts with the builtin.
func argvIsBuiltin(argv []string, bin string) bool {
	return len(argv) > 0 && argv[0] == bin
}

// requestIDFromStderr finds the gateway JSON result line and extracts
// request_id. Unparseable stderr yields "" (caller prints it raw).
func requestIDFromStderr(stderr string) string {
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var lj struct {
			Sysh      int    `json:"sysh"`
			Class     string `json:"class"`
			RequestID string `json:"request_id"`
		}
		if json.Unmarshal([]byte(line), &lj) == nil && lj.Sysh == 1 && lj.Class == "approval_required" {
			return lj.RequestID
		}
	}
	return ""
}
