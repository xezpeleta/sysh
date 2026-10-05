package watch

import (
	"testing"
)

func TestHostInfoPollerFetchAndSkip(t *testing.T) {
	good := `{"mode":"enforcing","rules":3,"allow":1,"deny":1,"approval":1,"sha256":"abc","mtime":"x"}`
	p := &HostInfoPoller{
		Addrs: map[string]string{
			"up":       "10.0.0.1:22",
			"down":     "10.0.0.2:22",
			"recon":    "10.0.0.3:22",
			"garbage":  "10.0.0.4:22",
		},
		SSHRun: func(addr string, argv []string) ([]byte, error) {
			switch addr {
			case "10.0.0.1:22":
				return []byte(good), nil
			case "10.0.0.4:22":
				return []byte("usage: sysh policy ..."), nil
			}
			return nil, errHostUnreachable
		},
		Put: func(host string, hp *HostPolicy) {
			switch host {
			case "up":
				if hp == nil || hp.Mode != "enforcing" || hp.Rules != 3 {
					t.Fatalf("up: got %+v", hp)
				}
			case "recon":
				t.Fatal("recon host must be skipped, not fetched")
			case "down", "garbage":
				if hp != nil {
					t.Fatalf("%s: expected nil, got %+v", host, hp)
				}
			}
		},
		HostState: func(name string) string {
			if name == "recon" {
				return "reconnecting"
			}
			return "following"
		},
	}
	p.pollOnce()
}

func TestHostInfoPollerNilSafe(t *testing.T) {
	p := &HostInfoPoller{
		Addrs:  map[string]string{"a": "10.0.0.9:22"},
		SSHRun: func(addr string, argv []string) ([]byte, error) { return nil, errHostUnreachable },
	}
	p.pollOnce() // no Put, no HostState: must not panic
	}


var errHostUnreachable = &fakeSSHErr{}

type fakeSSHErr struct{}

func (*fakeSSHErr) Error() string { return "ssh: connect timeout" }
