package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"io"
	"strings"
	"testing"

	"github.com/xezpeleta/sysh/internal/approval"
)

// fakeBody builds a server-shaped request JSON for a valid id.
func fakeBody(t *testing.T, argv []string, key string) (id string, body []byte) {
	t.Helper()
	id = approval.ID(argv, key)
	b, err := json.Marshal(map[string]any{
		"id":          id,
		"key":         key,
		"fingerprint": "SHA256:test",
		"argv":        argv,
		"time":        "2026-10-04T18:00:00+02:00",
	})
	if err != nil {
		t.Fatal(err)
	}
	return id, b
}

func withTestConfig(t *testing.T, extra string) {
	t.Helper()
	dir := t.TempDir()
	cfg := "default = \"h1\"\n\n[hosts.h1]\naddress = \"203.0.113.10\"\n" + extra
	p := filepath.Join(dir, "hosts.toml")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	old := configPath
	configPath = p
	t.Cleanup(func() { configPath = old })
}

func TestApproveClientFullFlow(t *testing.T) {
	withTestConfig(t, "\n[approver]\nkey = \"/tmp/approver-sk\"\n")
	id, body := fakeBody(t, []string{"/usr/sbin/reboot"}, "sy/h1")

	var submitted []string
	var gotStdin string
	oldSSH, oldSign := sshExec, sshSign
	sshExec = func(addr string, args []string, stdin io.Reader, out *bytes.Buffer) int {
		if addr != "203.0.113.10" {
			t.Errorf("addr %q", addr)
		}
		switch {
		case strings.HasSuffix(strings.Join(args, " "), "--show"):
			out.Write(body)
			return 0
		case args[len(args)-1] == "--sig":
			b, _ := io.ReadAll(stdin)
			gotStdin = string(b)
			submitted = args
			return 0
		}
		t.Errorf("unexpected ssh args %v", args)
		return 1
	}
	sshSign = func(key, file string) error {
		if key != "/tmp/approver-sk" {
			t.Errorf("key %q", key)
		}
		return os.WriteFile(file+".sig", []byte("SIGNATURE"), 0o600)
	}
	t.Cleanup(func() { sshExec, sshSign = oldSSH, oldSign })

	if code := cmdApproveClient([]string{id}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if len(submitted) != 4 || submitted[2] != id || submitted[3] != "--sig" {
		t.Fatalf("submit args %v", submitted)
	}
	if gotStdin != "SIGNATURE" {
		t.Fatalf("sig stdin %q", gotStdin)
	}
}

func TestApproveClientHostArg(t *testing.T) {
	withTestConfig(t, "")
	id, _ := fakeBody(t, []string{"/usr/bin/id"}, "sy/h1")
	var seen string
	oldSSH, oldSign := sshExec, sshSign
	sshExec = func(addr string, args []string, stdin io.Reader, out *bytes.Buffer) int {
		seen = addr
		return 1 // refuse early on purpose
	}
	sshSign = oldSign
	t.Cleanup(func() { sshExec, sshSign = oldSSH, oldSign })
	cmdApproveClient([]string{"h1", id})
	if seen != "203.0.113.10" {
		t.Fatalf("host resolution: %q", seen)
	}
}

func TestApproveClientRefusals(t *testing.T) {
	withTestConfig(t, "\n[approver]\nkey = \"/tmp/k\"\n")
	id, body := fakeBody(t, []string{"/usr/sbin/reboot"}, "sy/h1")

	otherID := "req_000000000000"
	cases := []struct {
		name string
		body []byte
	}{
		{"server returned different id", bytes.ReplaceAll(body, []byte(id), []byte(otherID))},
		{"tampered argv", bytes.Replace(body, []byte("/usr/sbin/reboot"), []byte("/bin/rm -rf /x"), 1)},
		{"garbage json", []byte("not json")},
	}
	for _, tc := range cases {
		oldSSH, oldSign := sshExec, sshSign
		sshExec = func(addr string, args []string, stdin io.Reader, out *bytes.Buffer) int {
			if args[len(args)-1] == "--show" {
				out.Write(tc.body)
				return 0
			}
			t.Errorf("%s: submit must not run", tc.name)
			return 1
		}
		sshSign = func(key, file string) error {
			t.Errorf("%s: signing must not run", tc.name)
			return nil
		}
		if code := cmdApproveClient([]string{id}); code == 0 {
			t.Errorf("%s: accepted", tc.name)
		}
		sshExec, sshSign = oldSSH, oldSign
	}
}

func TestApproveClientNoKeyConfigured(t *testing.T) {
	withTestConfig(t, "")
	id, body := fakeBody(t, []string{"/usr/bin/id"}, "sy/h1")
	oldSSH, oldSign := sshExec, sshSign
	sshExec = func(addr string, args []string, stdin io.Reader, out *bytes.Buffer) int {
		out.Write(body)
		return 0
	}
	t.Cleanup(func() { sshExec, sshSign = oldSSH, oldSign })
	if code := cmdApproveClient([]string{id}); code == 0 {
		t.Fatal("missing approver key must fail")
	}
}

func TestApproveClientSignFailureSubmitsNothing(t *testing.T) {
	withTestConfig(t, "\n[approver]\nkey = \"/tmp/k\"\n")
	id, body := fakeBody(t, []string{"/usr/bin/id"}, "sy/h1")
	oldSSH, oldSign := sshExec, sshSign
	sshExec = func(addr string, args []string, stdin io.Reader, out *bytes.Buffer) int {
		if args[len(args)-1] == "--sig" {
			t.Error("must not submit after failed signing")
		}
		out.Write(body)
		return 0
	}
	sshSign = func(key, file string) error { return os.ErrPermission }
	t.Cleanup(func() { sshExec, sshSign = oldSSH, oldSign })
	if code := cmdApproveClient([]string{id}); code == 0 {
		t.Fatal("sign failure must fail")
	}
}

func TestApproveClientBadArgs(t *testing.T) {
	for _, a := range [][]string{{}, {"not-an-id"}, {"req_zzz"}, {"-k"}} {
		if code := cmdApproveClient(a); code != 64 {
			t.Errorf("args %v: want 64, got %d", a, code)
		}
	}
}
