package control

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/xezpeleta/sysh/internal/policy"
)

// cmdDoctor verifies the effective configuration (§14.6): the sy user,
// filesystem state, effective sshd config for user sy, supplementary
// groups, yama, auditd, user-manager scope support, and the installed
// policy. FAIL lines exit 1; WARN lines do not.
func cmdDoctor(args []string) int {
	fails, warns := 0, 0
	ok := func(name, detail string) { fmt.Printf("ok    %-24s %s\n", name, detail) }
	warn := func(name, detail string) { fmt.Printf("WARN  %-24s %s\n", name, detail); warns++ }
	fail := func(name, detail string) { fmt.Printf("FAIL  %-24s %s\n", name, detail); fails++ }
	info := func(name, detail string) { fmt.Printf("info   %-24s %s\n", name, detail) }

	// --- sy user
	u, err := user.Lookup("sy")
	if err != nil {
		fail("user sy", "does not exist (reinstall the package)")
		return done(fails, warns)
	}
	uid, _ := strconv.Atoi(u.Uid)
	// shell & home from /etc/passwd directly (user.User is gecos)
	if shell, err := userShell("sy"); err == nil {
		if shell == "/usr/bin/sysh" {
			ok("sy shell", shell)
		} else {
			fail("sy shell", shell+" (expected /usr/bin/sysh)")
		}
	}
	if u.HomeDir == "/var/lib/sysh" {
		ok("sy home", u.HomeDir)
	} else {
		warn("sy home", u.HomeDir+" (expected /var/lib/sysh)")
	}
	if fi, err := os.Lstat(u.HomeDir); err == nil && fi.Mode().Perm()&0o022 == 0 && statUIDCtl(fi) == 0 {
		ok("sy home perms", "root-owned, not group/world-writable")
	} else {
		fail("sy home perms", "must be root-owned and not group/world-writable")
	}

	// --- supplementary groups (§4.2): the documented opt-in is
	// systemd-journal with the flag file present; nothing else.
	gids := groupIDs("sy")
	journalOptIn := fileExists(flagsDir + "/journal-group")
	bad := []string{}
	for _, g := range gids {
		switch g {
		case "sy":
		case "systemd-journal":
			if !journalOptIn {
				bad = append(bad, g+" (no opt-in flag; run: sysh journal-group enable or remove the group)")
			}
		default:
			bad = append(bad, g)
		}
	}
	if len(bad) == 0 {
		ok("sy groups", strings.Join(gids, ","))
	} else {
		fail("sy groups", strings.Join(bad, ", "))
	}

	// --- linger / persistence tripwires (§6.6)
	if _, lpErr := exec.LookPath("loginctl"); lpErr != nil {
		warn("linger", "loginctl unavailable")
	} else if out, err := exec.Command("/usr/bin/loginctl", "show-user", "sy", "-p", "Linger").Output(); err == nil {
		if strings.TrimSpace(string(out)) == "Linger=no" {
			ok("linger", "no")
		} else {
			warn("linger", strings.TrimSpace(string(out)))
		}
	} else {
		// loginctl exits non-zero when sy has no registered user record
		// yet (first login not happened) — which implies Linger=no.
		ok("linger", "no (no user record yet)")
	}
	if !fileExists("/var/spool/cron/crontabs/sy") {
		ok("crontab", "empty")
	} else {
		warn("crontab", "/var/spool/cron/crontabs/sy exists — inspect and remove it")
	}
	for _, f := range []string{"/etc/cron.allow", "/etc/at.allow"} {
		if fileExists(f) && userInFile(f, "sy") {
			fail("persistence allow", "sy is listed in "+f)
		}
	}

	// --- /etc/sysh state
	for _, e := range []struct{ path, want string }{
		{etcDir, "dir 0755 root:root"},
		{policyPath, "file 0644 root:root"},
		{authKeysPath, "file 0644 root:root"},
		{keysMapPath, "file 0644 root:root"},
	} {
		fi, err := os.Lstat(e.path)
		switch {
		case os.IsNotExist(err):
			if e.path != policyPath && e.path != keysMapPath && e.path != authKeysPath {
				fail("etc", e.path+" missing")
			} else {
				warn("etc", e.path+" not installed yet")
			}
		case err != nil:
			fail("etc", e.path+": "+err.Error())
		case statUIDCtl(fi) != 0 || fi.Mode().Perm()&0o022 != 0:
			fail("etc", fmt.Sprintf("%s: uid=%d mode=%o", e.path, statUIDCtl(fi), fi.Mode().Perm()))
		default:
			ok("etc", e.path)
		}
	}

	// --- volatile state (tmpfiles.d)
	runChecks := []struct {
		path string
		mode os.FileMode
		grp  string
	}{
		{"/run/sysh", 0o755, "root"},
		{"/run/sysh/requests", 0o730, "sy"},
		{"/run/sysh/results", 0o750, "sy"},
		{"/run/sysh-tripwire", 0o1777, "root"},
	}
	for _, rc := range runChecks {
		fi, err := os.Lstat(rc.path)
		if err != nil {
			fail("run", rc.path+" missing (run: systemd-tmpfiles --create /usr/lib/tmpfiles.d/sysh.conf)")
			continue
		}
		// Mode.Perm() drops special bits; check the sticky bit separately
		// (tripwire is deliberately 1777).
		perm := uint32(fi.Mode().Perm())
		sticky := fi.Mode()&os.ModeSticky != 0
		expPerm := uint32(rc.mode) & 0o777
		expSticky := uint32(rc.mode)&0o1000 != 0
		if perm != expPerm || sticky != expSticky {
			fail("run", fmt.Sprintf("%s: mode %o, expected %o", rc.path, perm|stickyOct(sticky), rc.mode))
			continue
		}
		if g := groupOf(fi); g != rc.grp {
			fail("run", fmt.Sprintf("%s: group %s, expected %s", rc.path, g, rc.grp))
			continue
		}
		ok("run", rc.path)
	}

	// --- effective sshd config for user sy (§5.3)
	sshd := sshdBinary()
	if sshd == "" {
		warn("sshd", "sshd binary not found")
	} else if out, err := exec.Command(sshd, "-T", "-C", "user=sy,host=localhost,addr=127.0.0.1").Output(); err != nil {
		fail("sshd", "sshd -T failed: "+strings.TrimSpace(err.Error()))
	} else {
		cfg := parseSSHD(string(out))
		want := map[string]string{
			"authorizedkeysfile":  "/etc/sysh/authorized_keys",
			"authenticationmethods": "publickey",
			"exposeauthinfo":      "yes",
			"permittty":           "no",
			"disableforwarding":   "yes",
			"x11forwarding":       "no",
			"allowagentforwarding": "no",
			"permittunnel":        "no",
			"permituserrc":        "no",
		}
		drift := []string{}
		for k, v := range want {
			if cfg[strings.ToLower(k)] != v {
				drift = append(drift, fmt.Sprintf("%s=%s (want %s)", k, cfg[strings.ToLower(k)], v))
			}
		}
		if len(drift) == 0 {
			ok("sshd", "effective config for user sy is correct")
		} else {
			fail("sshd", strings.Join(drift, ", "))
		}
	}

	// --- yama ptrace_scope (§6.7)
	if data, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); err == nil {
		if v, _ := strconv.Atoi(strings.TrimSpace(string(data))); v >= 1 {
			ok("yama", "ptrace_scope="+strings.TrimSpace(string(data)))
		} else {
			warn("yama", "ptrace_scope="+strings.TrimSpace(string(data))+" (>=1 recommended; DUMPABLE=0 mitigates)")
		}
	}

	// --- auditd (§8.4)
	polInstalled := fileExists(policyPath)
	permissive := false
	if polInstalled {
		if p, _, _, err := policy.Load(policyPath, 0); err == nil {
			permissive = p.Mode == policy.ModePermissive
			findings := policy.Lint(p, policy.RealFS())
			errs := 0
			for _, f := range findings {
				if f.Severity == policy.SevError {
					errs++
				}
				fmt.Println("      policy: " + f.String())
			}
			if errs == 0 {
				ok("policy lint", fmt.Sprintf("%d rules, mode=%s", len(p.Rules), p.Mode))
			} else {
				fail("policy lint", fmt.Sprintf("%d error(s)", errs))
			}
		} else {
			fail("policy load", err.Error())
		}
	} else {
		warn("policy", "no policy installed (agent channel will fail closed)")
	}
	auditActive := auditRulesActive()
	switch {
	case auditActive:
		ok("auditd", "sysh-scoped rules active")
	case fileExists("/etc/audit/rules.d/60-sysh.rules"):
		fail("auditd", "rules file present but not loaded (run: augenrules --load)")
	case permissive:
		fail("auditd", "permissive mode requires auditd integration (§6.6)")
	default:
		warn("auditd", "integration not installed (optional in enforcing mode)")
	}

	// --- user manager / scope support (§6.7)
	if out, err := exec.Command("/usr/bin/systemctl", "is-active", fmt.Sprintf("user@%d.service", uid)).Output(); err == nil && strings.TrimSpace(string(out)) == "active" {
		ctlPath := fmt.Sprintf("/sys/fs/cgroup/user.slice/user-%d.slice/user@%d.service/cgroup.controllers", uid, uid)
		if data, err := os.ReadFile(ctlPath); err == nil {
			have := string(data)
			if strings.Contains(have, "memory") && strings.Contains(have, "pids") {
				ok("user manager", "active, memory+pids delegated")
			} else {
				warn("user manager", "active but memory/pids not delegated; gateway falls back to no-scope exec")
			}
		} else {
			warn("user manager", "active; delegation undetermined")
		}
	} else {
		// Normal between agent logins: pam_systemd starts the user
		// manager at login, before the shell runs — the first agent
		// command after boot races it only occasionally, and the
		// gateway's no-scope fallback covers that. Informational.
		info("user manager", "not running (normal between logins; starts at agent login via PAM; rare first-command races use the no-scope fallback)")
	}

	// --- journald lost-message check (§8.2)
	if _, err := exec.Command("/usr/bin/journalctl", "-t", "sysh", "-n", "1", "--output", "cat").Output(); err == nil {
		ok("journal", "sysh events readable")
	}
	if out, err := exec.Command("/usr/bin/journalctl", "-u", "systemd-journald", "--since", "-24h", "--output", "cat").Output(); err == nil {
		if n := strings.Count(string(out), "Suppressed"); n > 0 {
			warn("journal drops", fmt.Sprintf("%d suppression notice(s) from systemd-journald in 24h", n))
		} else {
			ok("journal drops", "none in 24h")
		}
	}

	// --- gateway binary
	if fi, err := os.Lstat("/usr/bin/sysh"); err == nil && statUIDCtl(fi) == 0 && fi.Mode().Perm()&0o022 == 0 {
		ok("gateway binary", "/usr/bin/sysh")
	} else {
		fail("gateway binary", "/usr/bin/sysh must exist, root-owned, not group/world-writable")
	}

	return done(fails, warns)
}

func done(fails, warns int) int {
	fmt.Printf("\n%d failure(s), %d warning(s)\n", fails, warns)
	if fails > 0 {
		return 1
	}
	return 0
}

func sshdBinary() string {
	for _, p := range []string{"/usr/sbin/sshd", "/sbin/sshd", "/usr/bin/sshd"} {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

func parseSSHD(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			m[strings.ToLower(fields[0])] = fields[1]
		}
	}
	return m
}

func fileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func userInFile(path, user string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == user {
			return true
		}
	}
	return false
}

func userShell(name string) (string, error) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) == 7 && f[0] == name {
			return f[6], nil
		}
	}
	return "", fmt.Errorf("not found")
}

func groupIDs(name string) []string {
	out, err := exec.Command("/usr/bin/id", "-nG", name).Output()
	if err != nil {
		return nil
	}
	return strings.Fields(string(out))
}

func groupOf(fi os.FileInfo) string {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if g, err := user.LookupGroupId(strconv.Itoa(int(st.Gid))); err == nil {
			return g.Name
		}
	}
	return "?"
}

func statUIDCtl(fi os.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}

// stickyOct renders the sticky bit as its octal contribution for the
// diagnostic message (0 or 01000).
func stickyOct(on bool) uint32 {
	if on {
		return 0o1000
	}
	return 0
}
