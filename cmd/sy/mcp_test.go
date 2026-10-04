package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func withStubExec(t *testing.T, fn func(host string, argv []string) (execResult, error)) {
	t.Helper()
	old := execFunc
	execFunc = fn
	t.Cleanup(func() { execFunc = old })
}

// mcpCall sends one request line through mcpServe and decodes the response.
func mcpCall(t *testing.T, line string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	in := strings.NewReader(line + "\n")
	mcpServe(in, &out)
	var m map[string]any
	s := strings.TrimSpace(out.String())
	if s == "" {
		t.Fatal("no response")
	}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("bad json %q: %v", s, err)
	}
	return m
}

func resultOf(t *testing.T, resp map[string]any) map[string]any {
	t.Helper()
	if resp["error"] != nil {
		t.Fatalf("unexpected rpc error: %v", resp["error"])
	}
	return resp["result"].(map[string]any)
}

func textOf(t *testing.T, resp map[string]any) string {
	t.Helper()
	c := resultOf(t, resp)["content"].([]any)
	return c[0].(map[string]any)["text"].(string)
}

func TestInitialize(t *testing.T) {
	resp := mcpCall(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	res := resultOf(t, resp)
	if res["protocolVersion"] != mcpProtocol {
		t.Fatalf("protocol %v", res["protocolVersion"])
	}
}

func TestPing(t *testing.T) {
	resp := mcpCall(t, `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	_ = resultOf(t, resp)
}

func TestNotificationsGetNoResponse(t *testing.T) {
	var out bytes.Buffer
	in := strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	mcpServe(in, &out)
	if out.Len() != 0 {
		t.Fatalf("notification answered: %q", out.String())
	}
}

func TestToolsListHasThree(t *testing.T) {
	resp := mcpCall(t, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	tools := resultOf(t, resp)["tools"].([]any)
	if len(tools) != 3 {
		t.Fatalf("want 3 tools, got %d", len(tools))
	}
	for _, tv := range tools {
		td := tv.(map[string]any)
		if _, hasSchema := td["inputSchema"]; !hasSchema {
			t.Fatalf("tool %v missing inputSchema", td["name"])
		}
	}
}

func TestSyExecOk(t *testing.T) {
	withStubExec(t, func(host string, argv []string) (execResult, error) {
		if len(argv) != 1 || argv[0] != "/usr/bin/uptime" {
			t.Errorf("unexpected exec %q %v", host, argv)
		}
		return execResult{Exit: 0, Stdout: " up 3 days\n"}, nil
	})
	resp := mcpCall(t, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"sy_exec","arguments":{"argv":["/usr/bin/uptime"]}}}`)
	text := textOf(t, resp)
	if !strings.Contains(text, "up 3 days") || !strings.Contains(text, "exit 0") {
		t.Fatalf("text %q", text)
	}
	if resultOf(t, resp)["isError"] == true {
		t.Fatal("ok exec flagged as error")
	}
}

func TestSyExecApprovalRequired(t *testing.T) {
	withStubExec(t, func(host string, argv []string) (execResult, error) {
		return execResult{Exit: 30, Stderr: `{"sysh":1,"class":"approval_required","exit":30,"request_id":"req_abc123def456"}` + "\n"}, nil
	})
	resp := mcpCall(t, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"sy_exec","arguments":{"argv":["/usr/bin/touch","/tmp/x"]}}}`)
	text := textOf(t, resp)
	if !strings.Contains(text, "req_abc123def456") || !strings.Contains(text, "sysh approve") {
		t.Fatalf("approval text %q", text)
	}
	if resultOf(t, resp)["isError"] == true {
		t.Fatal("approval_required is a valid outcome, not a tool error")
	}
}

func TestSyExecDeniedIsError(t *testing.T) {
	withStubExec(t, func(host string, argv []string) (execResult, error) {
		return execResult{Exit: 125, Stderr: `{"sysh":1,"class":"denied"}` + "\n"}, nil
	})
	resp := mcpCall(t, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"sy_exec","arguments":{"argv":["/bin/rm","-rf","/"]}}}`)
	if resultOf(t, resp)["isError"] != true {
		t.Fatal("denied exec must be isError")
	}
}

func TestSyDocsPrefixesBuiltin(t *testing.T) {
	var got []string
	withStubExec(t, func(host string, argv []string) (execResult, error) {
		got = argv
		return execResult{Exit: 0, Stdout: "docs..."}, nil
	})
	mcpCall(t, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"sy_docs","arguments":{"argv":["runbook"]}}}`)
	if len(got) != 2 || got[0] != "sy-docs" || got[1] != "runbook" {
		t.Fatalf("argv %v", got)
	}
}

func TestSyPolicy(t *testing.T) {
	var got []string
	withStubExec(t, func(host string, argv []string) (execResult, error) {
		got = argv
		return execResult{Exit: 0, Stdout: "# policy\n"}, nil
	})
	mcpCall(t, `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"sy_policy","arguments":{"argv":["sy-policy"],"host":"web01"}}}`)
	if len(got) != 1 || got[0] != "sy-policy" {
		t.Fatalf("argv %v", got)
	}
}

func TestValidateArgv(t *testing.T) {
	if err := validateArgv(nil); err == nil {
		t.Fatal("empty argv must be rejected")
	}
	if err := validateArgv([]string{"/bin/echo", ""}); err == nil {
		t.Fatal("empty arg must be rejected")
	}
	if err := validateArgv([]string{"/bin/echo", "hello world"}); err == nil {
		t.Fatal("space in arg must be rejected client-side")
	}
	if err := validateArgv([]string{"/bin/echo", "héllo"}); err == nil {
		t.Fatal("non-ASCII must be rejected client-side")
	}
	if err := validateArgv([]string{"/bin/ls", "-la", "/tmp;rm"}); err != nil {
		t.Fatalf("printable ASCII without spaces must pass: %v", err)
	}
}

func TestUnknownMethodAndTool(t *testing.T) {
	resp := mcpCall(t, `{"jsonrpc":"2.0","id":9,"method":"nope"}`)
	if resp["error"] == nil {
		t.Fatal("want -32601")
	}
	withStubExec(t, func(host string, argv []string) (execResult, error) {
		return execResult{}, nil
	})
	resp = mcpCall(t, `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"sy_nuke","arguments":{"argv":["x"]}}}`)
	if resultOf(t, resp)["isError"] != true {
		t.Fatal("unknown tool must be isError")
	}
}

func TestRequestIDFromStderr(t *testing.T) {
	if rid := requestIDFromStderr("noise\n{\"sysh\":1,\"class\":\"approval_required\",\"request_id\":\"req_001122334455\"}\n"); rid != "req_001122334455" {
		t.Fatalf("rid %q", rid)
	}
	if rid := requestIDFromStderr("no json here"); rid != "" {
		t.Fatalf("rid %q", rid)
	}
}
