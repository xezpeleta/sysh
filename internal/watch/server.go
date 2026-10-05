// server.go — the localhost HTTP face of `sy watch`.
//
// Security posture: read-only, loopback by default. The Host header is
// validated against localhost forms so a malicious page the operator
// visits cannot DNS-rebind into the viewer (the classic local-web-tool
// attack). Nothing here can execute, approve, or write anywhere; the
// one action the surface allows is opening a terminal that RUNS the
// approval ceremony — the argv box, the typed confirmation, and the
// token gesture all happen there, fetched by the terminal itself.
package watch

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//go:embed web/index.html web/style.css web/app.js
var webFS embed.FS

// Server serves the viewer for one hub and poller.
type Server struct {
	Hub        *Hub
	Pending    func() []Pending // snapshot source
	ExtraHosts []HostStatus     // static hosts to report (tests/preview)

	// Hosts maps known host names to addresses; the launch endpoint
	// refuses anything not in the registry.
	Hosts map[string]string

	// LaunchApprove opens a terminal running "sy approve <host> <id>".
	// The browser can look and launch, never act: signing stays in
	// the terminal. nil disables the endpoint (copy-paste fallback).
	LaunchApprove LaunchApproveFunc

	// In-web ceremony (see ceremony.go). FetchRequest gathers the
	// argv and exact bytes at ceremony time; SignSubmit signs (the
	// token touch) and submits, with the operator's approver key
	// bound in at wiring time. nil disables the in-web path.
	Ceremonies   *CeremonyStore
	FetchRequest FetchRequestFunc
	SignSubmit   func(host, id string, body []byte) (string, error)

	// Agents correlates journal events per request id: is the filing
	// agent waiting, told-expired, or already answered? Nil = the
	// pending rows carry no agent line and /api/answers 404.
	Agents *Agents

	// SkipChallenge disables the typed-argument challenge (operator
	// opt-out via `sy watch --no-challenge`). The token touch remains
	// the wall against the agent; what is lost is the forced reading
	// of the argv — the anti-phishing layer.
	SkipChallenge bool
}

// Handler builds the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Static assets carry no validators and change between builds:
	// without Cache-Control the browser heuristic-caches them and an
	// operator staring at a stale UI after an upgrade is a support
	// case (live: an unbriefed-test operator did). The page is tiny;
	// always refetch.
	asset := func(name, ctype string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := webFS.ReadFile(name)
			w.Header().Set("Content-Type", ctype)
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write(body)
		})
	}
	// {$} matches the exact root; a bare "GET /" would swallow every
	// GET route that does not exist (the method-scoped API handlers
	// registered above would answer, but anything else would get
	// index.html with a 200).
	mux.Handle("GET /{$}", asset("web/index.html", "text/html; charset=utf-8"))
	mux.Handle("GET /style.css", asset("web/style.css", "text/css; charset=utf-8"))
	mux.Handle("GET /app.js", asset("web/app.js", "text/javascript; charset=utf-8"))

	mux.HandleFunc("GET /api/events", s.sseEvents)
	mux.HandleFunc("GET /api/hosts", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.hostList())
	})
	mux.HandleFunc("POST /api/approve", s.approveLaunch)
	mux.HandleFunc("POST /api/ceremony", requireSameOrigin(s.ceremonyStart))
	mux.HandleFunc("POST /api/ceremony/confirm", requireSameOrigin(s.ceremonyConfirm))

	mux.HandleFunc("GET /api/pending", func(w http.ResponseWriter, r *http.Request) {
		rows := []Pending{}
		if s.Pending != nil {
			rows = s.Pending()
		}
		s.Agents.augment(rows) // nil-safe
		writeJSON(w, rows)
	})
	mux.HandleFunc("GET /api/agents", func(w http.ResponseWriter, r *http.Request) {
		if s.Agents == nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, s.Agents.Recent(50))
	})

	return localOnly(mux)
}

// localOnly rejects requests whose Host header is not a localhost form
// (DNS-rebinding defense for a loopback-only tool).
func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			http.Error(w, "sy watch serves localhost only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hostList merges hub statuses with any extras.
func (s *Server) hostList() []HostStatus {
	out := s.Hub.Hosts()
	if len(out) == 0 && len(s.ExtraHosts) > 0 {
		return s.ExtraHosts
	}
	return out
}

// sseEvents streams the ring snapshot, then live events.
func (s *Server) sseEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	limit := 500
	if n := r.URL.Query().Get("limit"); n != "" {
		if v, err := strconv.Atoi(n); err == nil && v >= 0 && v <= 5000 {
			limit = v
		}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")

	ch, cancel := s.Hub.Subscribe()
	defer cancel()

	// Snapshot first (oldest first), so a refresh shows history.
	for _, ev := range s.Hub.Snapshot(limit) {
		if !writeSSE(w, ev) {
			return
		}
	}
	flusher.Flush()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			if !writeSSE(w, ev) {
				return
			}
			flusher.Flush()
		case <-keepalive.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, ev Event) bool {
	body, err := json.Marshal(ev)
	if err != nil {
		return true // skip undecodable events
	}
	_, err = fmt.Fprintf(w, "data: %s\n\n", body)
	return err == nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// ListenAndServe runs the HTTP server (convenience wrapper).
func (s *Server) ListenAndServe(addr string, logger *log.Logger) error {
	srv := &http.Server{Addr: addr, Handler: s.Handler()}
	if logger != nil {
		logger.Printf("sy watch: http://%s", addr)
	}
	return srv.ListenAndServe()
}

// approveLaunch opens a terminal running "sy approve <host> <id>".
// It is a launcher, nothing more: the argv box, the typed
// confirmation, and the token gesture all happen inside the spawned
// terminal, on bytes the terminal fetches from the server itself.
// The HTTP surface still has no exec, sign, or submit path.
func (s *Server) approveLaunch(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host string `json:"host"`
		ID   string `json:"id"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "bad json body", http.StatusBadRequest)
		return
	}
	if !ValidRequestID(body.ID) {
		http.Error(w, "bad request id", http.StatusBadRequest)
		return
	}
	if s.Hosts != nil {
		if _, ok := s.Hosts[body.Host]; !ok {
			http.Error(w, "unknown host", http.StatusNotFound)
			return
		}
	}
	// The id must correspond to something the operator can actually
	// see as pending — no launching terminals for invented ids.
	if s.Pending != nil {
		found := false
		for _, p := range s.Pending() {
			if p.Host == body.Host && p.ID == body.ID {
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "request not in pending snapshot", http.StatusNotFound)
			return
		}
	}
	if s.LaunchApprove == nil {
		http.Error(w, "terminal launch not available — copy the command instead", http.StatusServiceUnavailable)
		return
	}
	if !launchAllowed() {
		http.Error(w, "too many launches — wait a moment", http.StatusTooManyRequests)
		return
	}
	if err := s.LaunchApprove(body.Host, body.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "terminal opened — finish the ceremony there"})
}

// requireSameOrigin is the browser-boundary gate for the ceremony
// endpoints: a POST is a POST, so the server cannot tell a click from
// a scripted request — what it CAN do is make sure the request came
// from this page and not from some other website the operator has
// open. Browsers guarantee Sec-Fetch-Site (since 2020): it is
// "same-origin" only for requests issued by this page. Cross-site
// forms and fetches die here. Local same-user processes can spoof
// the header — but they can equally drive `sy approve` through a
// synthetic TTY; against them the token touch is the wall, as in the
// terminal ceremony.
func requireSameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			http.Error(w, "json content type required", http.StatusUnsupportedMediaType)
			return
		}
		if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "same-origin" {
			http.Error(w, "same-origin only: a visited web page cannot drive the ceremony — use the terminal", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// ceremonyStart opens the in-web ceremony for a pending request:
// fetches argv and the exact request bytes fresh, stores a one-shot
// ceremony, and returns what the modal must show. The argv shown is
// the argv that will be signed — one chain of custody.
func (s *Server) ceremonyStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host string `json:"host"`
		ID   string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "bad json body", http.StatusBadRequest)
		return
	}
	if !ValidRequestID(body.ID) {
		http.Error(w, "bad request id", http.StatusBadRequest)
		return
	}
	addr, ok := "", false
	if s.Hosts != nil {
		addr, ok = s.Hosts[body.Host]
		if !ok {
			http.Error(w, "unknown host", http.StatusNotFound)
			return
		}
	}
	if s.FetchRequest == nil || s.Ceremonies == nil {
		http.Error(w, "in-web ceremony not available — use the terminal", http.StatusServiceUnavailable)
		return
	}
	if !launchAllowed() {
		http.Error(w, "too many ceremonies — wait a moment", http.StatusTooManyRequests)
		return
	}
	info, err := s.FetchRequest(body.Host, addr, body.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if len(info.Argv) == 0 {
		http.Error(w, "request has no argv", http.StatusBadGateway)
		return
	}
	c := &Ceremony{
		Info:    *info,
		Token:   newCeremonyToken(),
		Prompt:  info.Argv[len(info.Argv)-1],
		Expires: time.Now().Add(CeremonyTTL),
	}
	s.Ceremonies.Put(c)
	writeJSON(w, map[string]any{
		"token":     c.Token,
		"id":        c.Info.ID,
		"host":      c.Info.Host,
		"key":       c.Info.Key,
		"argv":      c.Info.Argv,
		"age":       c.Info.AgeSec,
		"type":      c.Prompt,
		"challenge": !s.SkipChallenge,
	})
}

// ceremonyConfirm checks the typed argument, then signs and submits.
// The ceremony is one-shot: consumed by a right OR wrong typing, so
// retrying means starting over and reading the argv again.
func (s *Server) ceremonyConfirm(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host  string `json:"host"`
		ID    string `json:"id"`
		Token string `json:"token"`
		Typed string `json:"typed"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body); err != nil {
		http.Error(w, "bad json body", http.StatusBadRequest)
		return
	}
	c := s.Ceremonies.Take(body.ID, body.Token)
	if c == nil {
		http.Error(w, "ceremony expired or unknown — start again and read the argv", http.StatusGone)
		return
	}
	if s.SignSubmit == nil {
		http.Error(w, "in-web ceremony not available — use the terminal", http.StatusServiceUnavailable)
		return
	}
	if !s.SkipChallenge && body.Typed != c.Prompt {
		http.Error(w, "typed argument does not match — start again and read the argv", http.StatusBadRequest)
		return
	}
	result, err := s.SignSubmit(c.Info.Host, c.Info.ID, c.Info.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"result": result})
}
