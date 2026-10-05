// follower.go — one persistent journal follow per host, over the
// operator's root SSH channel, with reconnect and backoff.
package watch

import (
	"bufio"
	"io"
	"log"
	"net"
	"os/exec"
	"sync"
	"time"
)

// sshStreamFunc opens a streaming command on root@addr and returns its
// stdout plus a cancel that kills the underlying ssh. Seam for tests.
type sshStreamFunc func(addr string, argv []string) (io.Reader, func(), error)

// sshDestArgs builds the argv prefix for shelling out to ssh against
// root@addr. Addresses in hosts.toml may carry a port ("h:2222"); the
// ssh binary does not accept "user@host:port" as a destination (that
// is scp syntax), so a port becomes -p. ConnectTimeout bounds every
// root-channel use — a down host must cost 5 seconds, never the TCP
// hang that would stall the sequential approvals poller for minutes
// behind it — and BatchMode keeps the channel key-only: no prompt,
// anywhere, can hang the operator's tooling.
func sshDestArgs(addr string) []string {
	pre := []string{"-o", "ConnectTimeout=5", "-o", "BatchMode=yes"}
	if host, port, err := net.SplitHostPort(addr); err == nil && port != "" {
		return append(pre, "-p", port, "root@"+host)
	}
	return append(pre, "root@"+addr)
}

// realSSHStream shells out to ssh (the operator's own config, agent,
// and keys — exactly the transport `sy approve` uses).
func realSSHStream(addr string, argv []string) (io.Reader, func(), error) {
	full := append(sshDestArgs(addr), argv...)
	cmd := exec.Command("ssh", full...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	cmd.Stderr = io.Discard // status is tracked via reconnect state
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	cancel := func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	return stdout, cancel, nil
}

// Follower follows one host's sysh journal into the hub.
type Follower struct {
	Host  string // config name
	Addr  string // ssh address
	Since string // journalctl --since value (e.g. "-1h")

	Hub      *Hub
	Stream   sshStreamFunc                          // seam; normally realSSHStream
	ScanLine func(host, line string) (Event, error) // seam; normally parseEventLine
	Log      *log.Logger

	// Agents folds every parsed event into the per-request agent
	// tracker (agents.go). Nil = tracking off.
	Agents *Agents

	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewFollower wires a follower with production defaults.
func NewFollower(host, addr, since string, hub *Hub, logger *log.Logger) *Follower {
	return &Follower{
		Host:     host,
		Addr:     addr,
		Since:    since,
		Hub:      hub,
		Stream:   realSSHStream,
		ScanLine: parseEventLine,
		Log:      logger,
		stopCh:   make(chan struct{}),
	}
}

// Stop ends the follow loop.
func (f *Follower) Stop() {
	f.stopOnce.Do(func() { close(f.stopCh) })
}

// Follow runs until Stop: connect → stream → parse → hub; on break,
// reconnect with capped exponential backoff.
func (f *Follower) Follow() {
	if f.ScanLine == nil {
		f.ScanLine = parseEventLine
	}
	if f.Stream == nil {
		f.Stream = realSSHStream
	}
	if f.stopCh == nil {
		f.stopCh = make(chan struct{})
	}
	backoff := time.Second
	for {
		select {
		case <-f.stopCh:
			return
		default:
		}
		argv := []string{"journalctl", "-t", "sysh", "-o", "json", "-f", "--no-pager", "--since=" + f.Since}
		f.Hub.SetHost(f.Host, "reconnecting", "")
		r, cancel, err := f.Stream(f.Addr, argv)
		if err != nil {
			f.Hub.SetHost(f.Host, "reconnecting", err.Error())
			if !f.sleep(backoff) {
				return
			}
			backoff = growBackoff(backoff)
			continue
		}
		f.Hub.SetHost(f.Host, "following", "")
		backoff = time.Second

		err = f.pump(r)
		cancel()
		f.Hub.SetHost(f.Host, "reconnecting", errString(err))
		if !f.sleep(time.Second) {
			return
		}
	}
}

// pump reads journal lines until the stream breaks. A parse error on a
// single line is logged and skipped (one odd line must not blind the
// viewer); stream errors end the pump.
func (f *Follower) pump(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024) // argv can be long
	for sc.Scan() {
		select {
		case <-f.stopCh:
			return nil
		default:
		}
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		ev, err := f.ScanLine(f.Host, string(line))
		if err != nil {
			if f.Log != nil {
				f.Log.Printf("%s: %v", f.Host, err)
			}
			continue
		}
		f.Hub.Add(ev)
		f.Agents.Observe(ev) // nil-safe
	}
	return sc.Err()
}

// sleep waits d or until stopped; reports whether to continue.
func (f *Follower) sleep(d time.Duration) bool {
	select {
	case <-f.stopCh:
		return false
	case <-time.After(d):
		return true
	}
}

func growBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

func errString(err error) string {
	if err == nil {
		return "stream closed"
	}
	return err.Error()
}
