// watch.go — `sy watch`: the operator's read-only web viewer of every
// agent exec across all configured hosts (see internal/watch).
//
//	sy watch [--listen 127.0.0.1:7321] [--since 1h] [--no-open]
//
// One journal follow per host over the operator's root SSH channel
// (the same transport `sy approve` uses), one approvals poll, one
// localhost HTTP server. The browser can look, never act.
package main

import (
	"path/filepath"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/xezpeleta/sysh/internal/watch"
)

// watchListenDefault is loopback-only: this is the operator's window,
// not a service. Ports with no known collisions.
const watchListenDefault = "127.0.0.1:7321"

// watchApprovalsEvery is the pending-requests poll interval.
const watchApprovalsEvery = 5 * time.Second

func cmdWatch(args []string) int {
	listen := watchListenDefault
	since := "1h"
	noOpen := false
	noChallenge := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--listen", "-l":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "sy watch: --listen needs a value")
				return 64
			}
			i++
			listen = args[i]
		case "--since", "-s":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "sy watch: --since needs a value (e.g. 1h, 30m)")
				return 64
			}
			i++
			since = args[i]
		case "--no-open":
			noOpen = true
		case "--no-challenge":
			noChallenge = true
		default:
			fmt.Fprintf(os.Stderr, "sy watch: unknown flag %s\n", args[i])
			return 64
		}
	}

	hf, err := loadHosts()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if len(hf.Hosts) == 0 {
		fmt.Fprintln(os.Stderr, "sy watch: no hosts configured in hosts.toml")
		return 1
	}

	// Refuse non-loopback binds unless the operator insists with a
	// prefix; argv and keys are not for the network.
	if host, _, err := net.SplitHostPort(listen); err == nil && host != "" &&
		host != "localhost" && host != "127.0.0.1" && host != "::1" {
		fmt.Fprintf(os.Stderr, "sy watch: refusing non-loopback --listen %s\n", listen)
		return 64
	}

	logger := log.New(os.Stderr, "sy watch: ", log.LstdFlags)

	hub := watch.NewHub(5000)
	agents := watch.NewAgents()

	// One follower per host: config name → ssh address (port defaulted).
	hostAddrs := make(map[string]string, len(hf.Hosts))
	hostMeta := make(map[string]watch.HostMeta, len(hf.Hosts))
	for name, hc := range hf.Hosts {
		addr := hc.Address
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "22")
		}
		hostAddrs[name] = addr
		hostMeta[name] = watch.HostMeta{
			Address: addr,
			User:    hc.User,
			Key:     filepath.Base(hc.Key),
		}
		f := watch.NewFollower(name, addr, "-"+since, hub, logger)
		f.Agents = agents
		go f.Follow()
	}

	approverKey := ""
	if hf.Approver != nil {
		approverKey = hf.Approver.Key
	}

	poller := watch.NewApprovalPoller(hostAddrs, watchApprovalsEvery, nil)
	poller.HostState = func(name string) string {
		for _, st := range hub.Hosts() {
			if st.Name == name {
				return st.State
			}
		}
		return ""
	}
	go poller.Run()

	// Policy summaries for the hosts view: read-only `sysh policy
	// show --json` over the same root channel, every couple of
	// minutes. Hosts on older sysh answer with an error and the
	// view simply omits the block.
	info := &watch.HostInfoPoller{
		Addrs:     hostAddrs,
		Every:     2 * time.Minute,
		Put:       hub.SetHostPolicy,
		HostState: poller.HostState,
		Log:       logger,
	}
	go info.Run()

	srv := &watch.Server{
		Hub:         hub,
		Pending:     poller.Snapshot,
		Agents:      agents,
		Hosts:       hostAddrs,
		HostMeta:    hostMeta,
		LaunchApprove: watch.RealLaunchApprove,
		Ceremonies:  watch.NewCeremonyStore(),
		SkipChallenge: noChallenge,
		FetchRequest: watch.RealFetchRequest,
		SignSubmit: func(host, id string, body []byte) (string, error) {
			return watch.RealSignSubmit(approverKey, host, hostAddrs[host], id, body)
		},
	}

	fmt.Fprintf(os.Stderr, "sy watch: %d host(s), journal history %s\n", len(hostAddrs), since)
	fmt.Fprintf(os.Stderr, "sy watch: open http://%s\n", listen)
	if !noOpen {
		openBrowser("http://" + listen)
	}
	if err := srv.ListenAndServe(listen, logger); err != nil {
		fmt.Fprintf(os.Stderr, "sy watch: %v\n", err)
		return 1
	}
	return 0
}

// openBrowser tries the platform opener; failure is silent (--no-open
// exists for exactly that case).
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		return
	}
	_ = cmd.Start()
}
