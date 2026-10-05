// tail.go — `sy tail`: the terminal-native sibling of `sy watch`.
//
//	sy tail [host] [--since 10m]
//
// Every host's sysh journal followed over the operator's root SSH,
// multiplexed into one stdout stream. No web, no browser: pipes and
// grep are the UI. Colors when stdout is a TTY, plain when not.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xezpeleta/sysh/internal/watch"
	"golang.org/x/sys/unix"
)

func cmdTail(args []string) int {
	hostName := ""
	since := "10m"
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--since" || args[i] == "-s":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "sy tail: --since needs a value (e.g. 1h, 30m)")
				return 64
			}
			i++
			since = args[i]
		case strings.HasPrefix(args[i], "-"):
			fmt.Fprintf(os.Stderr, "sy tail: unknown flag %s\n", args[i])
			return 64
		default:
			if hostName != "" {
				fmt.Fprintln(os.Stderr, "usage: sy tail [host] [--since 10m]")
				return 64
			}
			hostName = args[i]
		}
	}

	hf, err := loadHosts()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	// Which hosts: the named one, or all of them.
	names := make([]string, 0, len(hf.Hosts))
	if hostName != "" {
		if _, ok := hf.Hosts[hostName]; !ok {
			fmt.Fprintf(os.Stderr, "sy tail: no such host %q in hosts.toml\n", hostName)
			return 1
		}
		names = append(names, hostName)
	} else {
		for name := range hf.Hosts {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		fmt.Fprintln(os.Stderr, "sy tail: no hosts configured in hosts.toml")
		return 1
	}

	color := isTTY(os.Stdout)

	hub := watch.NewHub(1000)
	followers := make([]*watch.Follower, 0, len(names))
	for _, name := range names {
		hc := hf.Hosts[name]
		addr := hc.Address
		f := watch.NewFollower(name, addr, "-"+since, hub, nil)
		go f.Follow()
		followers = append(followers, f)
		fmt.Fprintf(os.Stderr, "sy tail: following %s\n", name)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		for _, f := range followers {
			f.Stop()
		}
	}()

	ch, cancel := hub.Subscribe()
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "sy tail: stopped")
			return 0
		case ev := <-ch:
			fmt.Fprintln(os.Stdout, formatTailLine(ev, color))
		}
	}
}

// ANSI colors, used only on a TTY.
const (
	cReset  = "\x1b[0m"
	cGreen  = "\x1b[32m"
	cRed    = "\x1b[31m"
	cAmber  = "\x1b[33m"
	cBlue   = "\x1b[34m"
	cGray   = "\x1b[90m"
)

// formatTailLine renders one event:
//
//	21:26:03 web01 sy/web01 allow /usr/bin/uptime (exit 0, 213ms)
//
// privileged execs carry [root]; the decision word is colored by class.
func formatTailLine(ev watch.Event, color bool) string {
	ts := "?"
	if t, err := time.Parse(time.RFC3339, ev.TS); err == nil {
		ts = t.Local().Format("15:04:05")
	}

	decision := ev.Decision
	priv := ""
	if ev.Priv {
		priv = " [root]"
	}
	outcome := ""
	if ev.Exit != nil {
		outcome = fmt.Sprintf(" (exit %d", *ev.Exit)
		if ev.DurMS != nil {
			outcome += fmt.Sprintf(", %dms", *ev.DurMS)
		}
		outcome += ")"
	}

	if color {
		var dc string
		switch ev.Decision {
		case "allow", "builtin", "privileged", "approve":
			dc = cGreen
		case "deny", "malformed", "lockdown", "internal", "timeout", "reject":
			dc = cRed
		case "request":
			dc = cAmber
		case "result":
			dc = cBlue
		default:
			dc = cGray
		}
		if priv != "" {
			priv = cAmber + priv + cReset
		}
		argv := strings.Join(ev.Argv, " ") + cGray + outcome + cReset
		return fmt.Sprintf("%s%s%s %s%s%s %s%s%s %s%s%s%s %s",
			cGray, ts, cReset,
			cBlue, ev.Host, cReset,
			cGray, ev.Key, cReset,
			dc, decision, cReset, priv,
			argv)
	}
	return fmt.Sprintf("%s %s %s %s%s %s%s",
		ts, ev.Host, ev.Key, decision, priv,
		strings.Join(ev.Argv, " "), outcome)
}

// isTTY reports whether f is a terminal (colors only for humans).
func isTTY(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}
