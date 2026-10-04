// server.go — the localhost HTTP face of `sy watch`.
//
// Security posture: read-only, loopback by default. The Host header is
// validated against localhost forms so a malicious page the operator
// visits cannot DNS-rebind into the viewer (the classic local-web-tool
// attack). Nothing here can execute, approve, or write anywhere.
package watch

import (
	"embed"
	"encoding/json"
	"fmt"
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
}

// Handler builds the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		body, _ := webFS.ReadFile("web/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("GET /style.css", func(w http.ResponseWriter, r *http.Request) {
		body, _ := webFS.ReadFile("web/style.css")
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("GET /app.js", func(w http.ResponseWriter, r *http.Request) {
		body, _ := webFS.ReadFile("web/app.js")
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write(body)
	})

	mux.HandleFunc("GET /api/events", s.sseEvents)
	mux.HandleFunc("GET /api/hosts", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.hostList())
	})
	mux.HandleFunc("GET /api/pending", func(w http.ResponseWriter, r *http.Request) {
		rows := []Pending{}
		if s.Pending != nil {
			rows = s.Pending()
		}
		writeJSON(w, rows)
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
