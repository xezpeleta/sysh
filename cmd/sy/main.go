// sy — the agent-side client for sysh-managed hosts (PROJECT.md §1.1,
// §10). One binary, two faces:
//
//	sy mcp    stdio MCP server for agent harnesses (tools: sy_exec,
//	          sy_docs, sy_policy) — unprivileged by construction, it
//	          connects as the sy user over plain SSH and holds no
//	          root power of any kind
//	sy approve / sy approvals / sy watch
//	          operator-side: the approval ceremony (signing gesture
//	          in a real TTY), the pending list, and the read-only web
//	          view of agent execs (loopback, journal is the truth)
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
	case "watch":
		os.Exit(cmdWatch(os.Args[2:]))
	case "tail":
		os.Exit(cmdTail(os.Args[2:]))
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
	fmt.Fprintln(os.Stderr, "  sy watch [--listen ..]     read-only web view of agent execs across hosts")
	fmt.Fprintln(os.Stderr, "  sy tail [host]             multiplexed live journal tail (terminal)")
}
