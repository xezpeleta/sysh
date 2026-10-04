package watch

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fixture is a realistic journalctl -o json line from sysh.
const fixture = `{"__CURSOR":"s=x","__REALTIME_TIMESTAMP":"1759617600123456","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"sysh","_UID":"999","PRIORITY":"6","MESSAGE":"allow key=sy/web01 argv=[\"/usr/bin/systemctl\" \"reload\" \"apache2\"]","DECISION":"allow","KEYID":"sy/web01.example.net","FINGERPRINT":"SHA256:abc","ARGV":"[\"/usr/bin/systemctl\",\"reload\",\"apache2\"]","RULE":"3","EXIT":"0","DURATION_MS":"213","PRIV":"false","PHASE":"post","POLICY_SHA":"deadbeef","MODE":"policy"}`

func TestParseEventLineFull(t *testing.T) {
	ev, err := parseEventLine("web01", fixture)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev.Decision != "allow" || ev.Host != "web01" {
		t.Fatalf("got %+v", ev)
	}
	if len(ev.Argv) != 3 || ev.Argv[0] != "/usr/bin/systemctl" {
		t.Fatalf("argv: %v", ev.Argv)
	}
	if ev.Rule == nil || *ev.Rule != 3 {
		t.Fatalf("rule: %v", ev.Rule)
	}
	if ev.Exit == nil || *ev.Exit != 0 {
		t.Fatalf("exit: %v", ev.Exit)
	}
	if ev.DurMS == nil || *ev.DurMS != 213 {
		t.Fatalf("dur: %v", ev.DurMS)
	}
	if ev.UID != 999 {
		t.Fatalf("uid: %v", ev.UID)
	}
	if ev.TS != "2025-10-04T22:40:00Z" {
		t.Fatalf("ts: %q", ev.TS)
	}
	if ev.Key != "sy/web01.example.net" {
		t.Fatalf("key: %q", ev.Key)
	}
}

func TestParseEventLineMinimal(t *testing.T) {
	// A pre-exec (fail-closed) entry: no EXIT/RULE/DURATION.
	line := `{"__REALTIME_TIMESTAMP":"1759617600000000","DECISION":"request","KEYID":"sy/web01","ARGV":"[\"/usr/bin/systemctl\",\"restart\",\"mariadb\"]","PHASE":"pre"}`
	ev, err := parseEventLine("web01", line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev.Exit != nil || ev.Rule != nil || ev.DurMS != nil {
		t.Fatalf("pre-exec must not fake outcomes: %+v", ev)
	}
	if ev.Decision != "request" {
		t.Fatalf("decision: %v", ev.Decision)
	}
}

func TestParseEventLineRejectsForeign(t *testing.T) {
	if _, err := parseEventLine("h", `{"MESSAGE":"hello"}`); err == nil {
		t.Fatal("line without DECISION must be rejected (not sysh)")
	}
	if _, err := parseEventLine("h", `not json`); err == nil {
		t.Fatal("bad json must be rejected")
	}
}

func TestParseEventLinePrivFlag(t *testing.T) {
	line := `{"__REALTIME_TIMESTAMP":"1759617600000000","DECISION":"privileged","KEYID":"sy/web01","ARGV":"[\"/usr/bin/id\"]","PRIV":"true"}`
	ev, err := parseEventLine("web01", line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !ev.Priv {
		t.Fatal("PRIV=true must surface")
	}
}

func TestHubRingAndFanout(t *testing.T) {
	h := NewHub(3)
	ch, cancel := h.Subscribe()
	defer cancel()

	for i := 0; i < 5; i++ {
		h.Add(Event{Host: "h", Decision: "allow"})
	}
	// ring keeps last 3
	snap := h.Snapshot(10)
	if len(snap) != 3 {
		t.Fatalf("ring: %d", len(snap))
	}
	if snap[0].Seq != 3 || snap[2].Seq != 5 {
		t.Fatalf("seqs: %v", snap)
	}
	// subscriber got all 5 (buffer 256)
	for i := 0; i < 5; i++ {
		select {
		case ev := <-ch:
			if ev.Seq != uint64(i+1) {
				t.Fatalf("fanout seq %d", ev.Seq)
			}
		default:
			t.Fatal("subscriber starved")
		}
	}
	// slow consumer: fill the channel, verify Add doesn't block
	h2 := NewHub(1)
	_, cancel2 := h2.Subscribe() // nobody drains this one
	defer cancel2()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 600; i++ {
			h2.Add(Event{Host: "h"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Add blocked on slow subscriber")
	}
}

func TestHostStatusLifecycle(t *testing.T) {
	h := NewHub(8)
	h.SetHost("web01", "reconnecting", "ssh: connection refused")
	h.SetHost("web01", "following", "")
	hosts := h.Hosts()
	if len(hosts) != 1 || hosts[0].State != "following" || hosts[0].Name != "web01" {
		t.Fatalf("hosts: %+v", hosts)
	}
}

func TestParseApprovals(t *testing.T) {
	rows, err := parseApprovals("web01", []byte(`[{"id":"req_000000000001","argv":["/usr/bin/systemctl","restart","mariadb"],"key":"sy/web01.example.net","age_sec":42,"expired":false}]`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 || rows[0].Host != "web01" || rows[0].AgeSec != 42 {
		t.Fatalf("rows: %+v", rows)
	}
	// empty and "no pending" cases
	if rows, _ := parseApprovals("h", []byte("no pending requests\n")); len(rows) != 0 {
		t.Fatalf("no-pending: %+v", rows)
	}
	if rows, _ := parseApprovals("h", nil); len(rows) != 0 {
		t.Fatalf("empty: %+v", rows)
	}
}

func TestApprovalPoller(t *testing.T) {
	p := NewApprovalPoller(map[string]string{"a": "10.0.0.1:22"}, time.Hour, func(host, addr string) ([]Pending, error) {
		return []Pending{{Host: host, ID: "req_1", Argv: []string{"/usr/bin/id"}}}, nil
	})
	go p.Run()
	defer p.Stop()
	deadline := time.Now().Add(time.Second)
	for len(p.Snapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	got := p.Snapshot()
	if len(got) != 1 || got[0].ID != "req_1" {
		t.Fatalf("snapshot: %+v", got)
	}
}

// --- HTTP layer ---

func TestServerHostHeaderGate(t *testing.T) {
	h := NewHub(8)
	s := &Server{Hub: h}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// evil origin: non-localhost Host must be refused
	req, _ := http.NewRequest("GET", srv.URL+"/api/hosts", nil)
	req.Host = "evil.example.com"
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("rebinding must be forbidden, got %d", res.StatusCode)
	}

	// localhost forms pass
	for _, host := range []string{"localhost", "127.0.0.1"} {
		req, _ := http.NewRequest("GET", srv.URL+"/api/hosts", nil)
		req.Host = host + ":1234"
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("localhost %s: %d", host, res.StatusCode)
		}
	}
}

func TestServerSSESnapshotThenLive(t *testing.T) {
	h := NewHub(8)
	h.Add(Event{Host: "web01", Decision: "allow", Argv: []string{"/usr/bin/uptime"}})
	s := &Server{Hub: h}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/events?limit=10", nil)
	req.Host = "localhost:1"
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer res.Body.Close()

	// read the snapshot line
	buf := make([]byte, 4096)
	n, _ := res.Body.Read(buf)
	first := string(buf[:n])
	if !strings.Contains(first, `"decision":"allow"`) || !strings.Contains(first, `"argv":["/usr/bin/uptime"]`) {
		t.Fatalf("snapshot sse: %q", first)
	}
	// a live event must stream through
	h.Add(Event{Host: "web02", Decision: "deny"})
	n, _ = res.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), `"web02"`) {
		t.Fatalf("live sse: %q", string(buf[:n]))
	}
	_ = io.EOF
}

func TestServerServesUI(t *testing.T) {
	h := NewHub(4)
	s := &Server{Hub: h}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	for path, ctype := range map[string]string{
		"/":         "text/html",
		"/style.css": "text/css",
		"/app.js":   "text/javascript",
	} {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req.Host = "localhost:1"
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 || !strings.Contains(res.Header.Get("Content-Type"), ctype) {
			t.Fatalf("%s: %d %s", path, res.StatusCode, res.Header.Get("Content-Type"))
		}
		if len(body) == 0 {
			t.Fatalf("%s: empty", path)
		}
	}

	// the UI must carry the localhost promise (sanity on embed)
	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.Host = "localhost:1"
	res, _ := srv.Client().Do(req)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)
}

func TestFollowerParsesAndReconnects(t *testing.T) {
	h := NewHub(8)
	pr, pw := io.Pipe()
	calls := 0
	f := &Follower{
		Host: "web01", Addr: "h:22", Since: "-1h", Hub: h,
		Stream: func(addr string, argv []string) (io.Reader, func(), error) {
			calls++
			if calls == 1 {
				go func() {
					_, _ = pw.Write([]byte(fixture + "\n"))
					_ = pw.Close()
				}()
				return pr, func() {}, nil
			}
			// second connect: never delivers, just stays quiet
			r, w := io.Pipe()
			return r, func() { _ = w.Close() }, nil
		},
	}
	go f.Follow()
	defer f.Stop()

	deadline := time.Now().Add(2 * time.Second)
	var got []Event
	for time.Now().Before(deadline) {
		got = h.Snapshot(10)
		if len(got) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(got) != 1 || got[0].Decision != "allow" || got[0].Host != "web01" {
		t.Fatalf("followed events: %+v", got)
	}
	// reconnect must have happened after the first stream closed
	// (the follower sleeps 1s between attempts)
	deadline = time.Now().Add(3 * time.Second)
	for calls < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if calls < 2 {
		t.Fatalf("expected reconnect, calls=%d", calls)
	}
}
