package control

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// cmdAudit tails the sy-side journal (§8.6): the operator channel's
// local view of agent activity. `sysh audit tail [-f] [N]`.
func cmdAudit(args []string) int {
	if len(args) == 0 || args[0] != "tail" {
		fmt.Fprintln(os.Stderr, "usage: sysh audit tail [-f] [lines]")
		return 64
	}
	follow := false
	n := "50"
	for _, a := range args[1:] {
		if a == "-f" || a == "--follow" {
			follow = true
		} else if v, err := strconv.Atoi(a); err == nil && v > 0 {
			n = a
		}
	}
	argv := []string{"journalctl", "-t", "sysh", "--output", "json", "-n", n}
	if follow {
		argv = append(argv, "-f")
	}
	cmd := exec.Command("journalctl", argv[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysh audit: %v\n", err)
		return 1
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "sysh audit: %v\n", err)
		return 1
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		fmt.Println(formatJournalJSON(sc.Text()))
	}
	cmd.Wait()
	return 0
}

// formatJournalJSON pretty-prints one journalctl --output=json record
// into a compact human-readable line, filtering to the useful fields.
func formatJournalJSON(line string) string {
	var rec map[string]string
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		// not a sysh record (boot lines etc.) — keep it identifiable
		return strings.TrimSpace(line)
	}
	get := func(key string) string { return rec[key] }

	ts := get("__REALTIME_TIMESTAMP")
	when := ""
	if v, err := strconv.ParseInt(ts, 10, 64); err == nil && ts != "" {
		when = formatJournalTime(v)
	}
	decision := get("DECISION")
	if decision == "" {
		decision = "event"
	}
	parts := []string{when, decision}
	if get("PHASE") == "pre" {
		parts = append(parts, "pre")
	}
	if k := get("KEYID"); k != "" {
		parts = append(parts, "key="+k)
	}
	if r := get("RULE"); r != "" && r != "-1" {
		parts = append(parts, "rule="+r)
	}
	if av := get("ARGV"); av != "" {
		parts = append(parts, "argv="+av)
	}
	if e := get("EXIT"); e != "" {
		parts = append(parts, "exit="+e)
	}
	if d := get("DURATION_MS"); d != "" && d != "0" {
		parts = append(parts, d+"ms")
	}
	if s := get("SCOPE"); s == "false" {
		parts = append(parts, "noscope")
	}
	if get("TRUNCATED") == "true" {
		parts = append(parts, "truncated")
	}
	if m := get("MESSAGE"); m != "" && !strings.HasPrefix(m, decision) {
		parts = append(parts, m)
	}
	return strings.Join(parts, " ")
}

func formatJournalTime(us int64) string {
	sec := us / 1e6
	return time.Unix(sec, 0).Format(time.RFC3339)
}

// cmdLockdown manages the tripwire (§6.5).
func cmdLockdown(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sysh lockdown clear|status")
		return 64
	}
	switch args[0] {
	case "status":
		if fileExists(tripwirePath) {
			fmt.Println("lockdown: ACTIVE — agent channel refuses everything")
			return 0
		}
		fmt.Println("lockdown: clear")
		return 0
	case "clear":
		if err := os.Remove(tripwirePath); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "sysh lockdown clear: %v\n", err)
			return 1
		}
		fmt.Println("lockdown cleared")
		return 0
	}
	fmt.Fprintln(os.Stderr, "usage: sysh lockdown clear|status")
	return 64
}

// cmdJournalGroup manages the documented opt-in for read-only journal
// access (§4.2): the only supplementary group sy may ever hold.
func cmdJournalGroup(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sysh journal-group enable|disable")
		return 64
	}
	switch args[0] {
	case "enable":
		if err := os.MkdirAll(flagsDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "sysh journal-group: %v\n", err)
			return 1
		}
		if err := atomicWrite(flagsDir+"/journal-group", []byte("opt-in\n"), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "sysh journal-group: %v\n", err)
			return 1
		}
		if err := addGroupMember("sy", "systemd-journal"); err != nil {
			fmt.Fprintf(os.Stderr, "sysh journal-group: %v\n (add sy to systemd-journal with: gpasswd -a sy systemd-journal)\n", err)
			return 1
		}
		fmt.Println("sy added to systemd-journal (flag recorded)")
		return 0
	case "disable":
		if err := delGroupMember("sy", "systemd-journal"); err != nil {
			fmt.Fprintf(os.Stderr, "sysh journal-group: %v\n (remove with: gpasswd -d sy systemd-journal)\n", err)
			return 1
		}
		_ = os.Remove(flagsDir + "/journal-group")
		fmt.Println("sy removed from systemd-journal")
		return 0
	}
	fmt.Fprintln(os.Stderr, "usage: sysh journal-group enable|disable")
	return 64
}

func addGroupMember(user, group string) error {
	gp, err := exec.LookPath("gpasswd")
	if err != nil {
		return err
	}
	return exec.Command(gp, "-a", user, group).Run()
}

func delGroupMember(user, group string) error {
	gp, err := exec.LookPath("gpasswd")
	if err != nil {
		return err
	}
	return exec.Command(gp, "-d", user, group).Run()
}
