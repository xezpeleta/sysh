package main

import (
	"strings"
	"testing"

	"github.com/xezpeleta/sysh/internal/watch"
)

func intp(v int) *int    { return &v }
func int64p(v int64) *int64 { return &v }

func TestFormatTailLinePlain(t *testing.T) {
	ev := watch.Event{
		Host: "web01", Key: "sy/web01",
		TS: "2026-10-04T19:26:03Z",
		Decision: "allow",
		Argv:     []string{"/usr/bin/uptime"},
		Exit:     intp(0), DurMS: int64p(213),
	}
	line := formatTailLine(ev, false)
	// TS renders in local time; only check structure around it.
	if !strings.HasSuffix(line, " web01 sy/web01 allow /usr/bin/uptime (exit 0, 213ms)") {
		t.Fatalf("plain: %q", line)
	}
	if strings.Contains(line, "\x1b[") {
		t.Fatal("plain mode must not emit ANSI")
	}
}

func TestFormatTailLinePrivAndRequest(t *testing.T) {
	ev := watch.Event{
		Host: "web01", Key: "sy/web01",
		TS: "2026-10-04T19:26:15Z",
		Decision: "request", Priv: true,
		Argv: []string{"/usr/bin/id"},
	}
	line := formatTailLine(ev, false)
	if !strings.Contains(line, "request [root] /usr/bin/id") {
		t.Fatalf("priv marker: %q", line)
	}
	if strings.Contains(line, "(exit") {
		t.Fatal("no outcome fields on a request")
	}
}

func TestFormatTailLineColor(t *testing.T) {
	ev := watch.Event{
		Host: "web01", Key: "sy/web01",
		TS: "2026-10-04T19:26:03Z",
		Decision: "deny",
		Argv:     []string{"/usr/bin/rm", "/etc/passwd"},
		Exit:     intp(125),
	}
	line := formatTailLine(ev, true)
	if !strings.Contains(line, "\x1b[31mdeny\x1b[0m") {
		t.Fatalf("deny must be red: %q", line)
	}
	if !strings.Contains(line, "\x1b[34mweb01\x1b[0m") {
		t.Fatalf("host must be blue: %q", line)
	}
}
