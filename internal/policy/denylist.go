package policy

// The package-maintained escape-hatch denylist (§7). Entries match the
// realpath AND basename of a rule's path — never argv[0] — so aliases
// and versioned names (python3.11, view, busybox) cannot slip past.
//
// Entries with argv constraints only trigger when those literals appear
// in the rule's argv (e.g. systemctl is only denied with --user; plain
// systemctl status/restart is the canonical allowed example).
//
// warn=true entries are the warning class: binaries that write files or
// open network connections without being executors (curl, wget, rsync)
// require an explicit ack = true on the rule before install proceeds.

type denyEntry struct {
	names  []string // glob patterns matched against basename and realpath
	argv   []string // literals that must all appear in rule argv to trigger
	warn   bool
	reason string
}

var denylist = []denyEntry{
	{
		names:  []string{"sh", "bash", "dash", "ash", "ksh*", "zsh*", "csh", "tcsh", "fish", "shell"},
		reason: "shell",
	},
	{
		names:  []string{"python*", "perl*", "ruby*", "node*", "nodejs*", "php*", "lua*", "tclsh*", "wish*", "Rscript", "awk", "gawk", "mawk", "guile*", "janet", "tcc"},
		reason: "interpreter",
	},
	{
		names:  []string{"env", "nohup", "setsid", "stdbuf", "timeout", "nice", "ionice", "xargs", "find", "tar", "git", "systemd-run", "strace", "ltrace", "gdb", "lldb*", "script", "screen", "tmux", "expect", "make", "busybox", "ld-linux*", "ld.so", "socat", "stdbuf*"},
		reason: "argv passthrough / execution wrapper",
	},
	{
		names:  []string{"ssh", "scp", "sftp", "nc", "ncat", "netcat", "socat", "telnet", "docker", "podman", "nerdctl", "kubectl", "sudo", "su", "doas", "mount", "umount", "pkexec", "nsenter", "unshare", "chroot", "fusermount*", "newgrp", "chfn", "chsh"},
		reason: "remote / privileged",
	},
	{
		names:  []string{"less", "more", "most", "vi", "vim*", "view", "nvim", "emacs*", "nano", "pico", "ed", "joe", "jove", "micro", "jed"},
		reason: "pager/editor (arbitrary command execution)",
	},
	{
		names:  []string{"crontab", "at", "atq", "atrm", "batch", "busctl", "loginctl"},
		reason: "persistence / session tool",
	},
	{
		names:  []string{"systemctl"},
		argv:   []string{"--user"},
		reason: "user-unit persistence",
	},
	// Warning class: file/network writers that are not executors.
	{
		names:  []string{"curl", "wget", "rsync", "ftp", "lftp", "aria2c", "youtube-dl", "yt-dlp"},
		warn:   true,
		reason: "writes files / opens network connections",
	},
}

// DenylistHit describes a denylist match on a rule.
type DenylistHit struct {
	Names  []string
	Reason string
	Warn   bool
}

// CheckDenylist evaluates a rule's (realpath, basename, argv) against
// the denylist. It returns the first matching entry, if any.
func CheckDenylist(realpath, basename string, argv []string) *DenylistHit {
	for _, e := range denylist {
		matched := matchAny(e.names, basename) || matchAny(e.names, realpath)
		if !matched {
			continue
		}
		if len(e.argv) > 0 {
			// all required literals must appear in argv
			all := true
			for _, want := range e.argv {
				found := false
				for _, a := range argv {
					if a == want {
						found = true
						break
					}
				}
				if !found {
					all = false
					break
				}
			}
			if !all {
				continue
			}
		}
		return &DenylistHit{Names: e.names, Reason: e.reason, Warn: e.warn}
	}
	return nil
}

// matchAny reports whether s matches any glob pattern.
func matchAny(pats []string, s string) bool {
	for _, p := range pats {
		if ok, err := globMatch(p, s); err == nil && ok {
			return true
		}
	}
	return false
}

// globMatch is a tiny glob: * wildcard, everything else literal
// (path.Match treats [ specially, which clashes with our entries).
func globMatch(pat, s string) (bool, error) {
	pi, si := 0, 0
	starP, starS := -1, 0
	for si < len(s) {
		if pi < len(pat) && pat[pi] == '*' {
			starP = pi
			pi++
			starS = si
		} else if pi < len(pat) && pat[pi] == s[si] {
			pi++
			si++
		} else if starP >= 0 {
			pi = starP + 1
			starS++
			si = starS
		} else {
			return false, nil
		}
	}
	for pi < len(pat) && pat[pi] == '*' {
		pi++
	}
	return pi == len(pat), nil
}
