// sy — the agent-side client for sysh-managed hosts (PROJECT.md §1.1,
// §10). One binary, one mode today:
//
//	sy mcp   stdio MCP server for agent harnesses (tools: sy_exec,
//	         sy_docs, sy_policy)
//
// Unprivileged by construction: it connects as the sy user over plain
// SSH, exactly like any other agent exec; it holds no approval,
// listing, or root power of any kind. What the host's policy allows is
// what these tools can do — nothing more.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(64)
	}
	switch os.Args[1] {
	case "mcp":
		cmdMCP(os.Args[2:])
	case "approve":
		os.Exit(cmdApproveClient(os.Args[2:]))
	case "approvals":
		os.Exit(cmdApprovalsClient(os.Args[2:]))
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(64)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  sy mcp                    stdio MCP server (sy_exec, sy_docs, sy_policy)")
	fmt.Fprintln(os.Stderr, "  sy approve [host] <id>    operator approval ceremony (YubiKey sign + submit)")
	fmt.Fprintln(os.Stderr, "  sy approvals [host]       list pending approval requests")
}
