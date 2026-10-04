// client.go — host config and the SSH exec path for `sy mcp`.
//
// Config: ~/.config/sy/hosts.toml (operator-machine side, never on the
// managed host):
//
//	default = "web01"
//
//	[hosts.web01]
//	address = "web01.example.net:22"   # host[:port], default port 22
//	user    = "sy"
//	key     = "/home/op/.config/sy/keys/web01.ed25519"
//
// Host keys are verified strictly against ~/.config/sy/known_hosts
// (fail closed; populate with ssh-keyscan -t ed25519,ed25519-sk host).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var version = "0.4.0~dev1"

// configPath and knownHostsPath are seams for tests.
var (
	configPath   = defaultConfigPath()
	knownHostsFn = defaultKnownHostsPath
)

func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "sy", "hosts.toml")
}

func defaultKnownHostsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "sy", "known_hosts")
}

// hostConfig is one managed host entry.
type hostConfig struct {
	Address string `toml:"address"`
	User    string `toml:"user"`
	Key     string `toml:"key"`
}

// hostsFile is the whole config.
type hostsFile struct {
	Default string                 `toml:"default"`
	Hosts   map[string]*hostConfig `toml:"hosts"`
}

// loadHosts reads the config; a missing file is an explicit error (an
// agent without hosts configured should not guess).
func loadHosts() (*hostsFile, error) {
	body, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("sy: hosts config %s: %v (create it: see usage docs)", configPath, err)
	}
	var hf hostsFile
	if err := toml.Unmarshal(body, &hf); err != nil {
		return nil, fmt.Errorf("sy: hosts config %s: %v", configPath, err)
	}
	return &hf, nil
}

// resolveHost picks the named host or the default.
func (hf *hostsFile) resolveHost(name string) (*hostConfig, error) {
	if name == "" {
		name = hf.Default
	}
	if name == "" {
		return nil, fmt.Errorf("sy: no host given and no default configured")
	}
	hc, ok := hf.Hosts[name]
	if !ok {
		return nil, fmt.Errorf("sy: no such host %q in %s", name, configPath)
	}
	if hc.User == "" {
		hc.User = "sy"
	}
	return hc, nil
}

// execResult is one remote exec outcome.
type execResult struct {
	Exit   int
	Stdout string
	Stderr string
}

// validateArgv rejects what the sysh gateway cannot even express:
// empty argv, empty args, non-printable or non-ASCII bytes, spaces
// inside args (the command string is whitespace-split server-side,
// §6). Everything else is the server's call — policy decides.
func validateArgv(argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("empty argv")
	}
	for i, a := range argv {
		if a == "" {
			return fmt.Errorf("argument %d is empty", i)
		}
		for _, r := range a {
			if r < 0x21 || r > 0x7e {
				return fmt.Errorf("argument %d contains a space or non-printable/non-ASCII byte (the remote gateway splits on whitespace and allows printable ASCII only)", i)
			}
		}
	}
	return nil
}

// execSSH runs one argv on a host as the configured user and returns
// stdout, stderr, and the passthrough exit code. The argv is joined
// with single spaces — exactly the grammar the gateway re-splits.
func execSSH(hc *hostConfig, argv []string) (execResult, error) {
	if err := validateArgv(argv); err != nil {
		return execResult{}, err
	}
	addr := hc.Address
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "22")
	}

	keyBody, err := os.ReadFile(hc.Key)
	if err != nil {
		return execResult{}, fmt.Errorf("sy: agent key %s: %v", hc.Key, err)
	}
	signer, err := ssh.ParsePrivateKey(keyBody)
	if err != nil {
		return execResult{}, fmt.Errorf("sy: agent key %s: %v", hc.Key, err)
	}

	khPath := knownHostsFn()
	if khPath == "" {
		return execResult{}, fmt.Errorf("sy: cannot locate known_hosts")
	}
	hkcb, err := knownhosts.New(khPath)
	if err != nil {
		return execResult{}, fmt.Errorf("sy: known_hosts %s: %v (populate with: ssh-keyscan -t ed25519 host >> %s)", khPath, err, khPath)
	}

	cfg := &ssh.ClientConfig{
		User:            hc.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hkcb,
		Timeout:         10 * time.Second,
	}
	conn, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return execResult{}, fmt.Errorf("sy: %s: %v", addr, err)
	}
	defer conn.Close()

	sess, err := conn.NewSession()
	if err != nil {
		return execResult{}, fmt.Errorf("sy: session: %v", err)
	}
	defer sess.Close()
	var outB, errB bytes.Buffer
	sess.Stdout = &outB
	sess.Stderr = &errB
	runErr := sess.Run(strings.Join(argv, " "))

	res := execResult{Exit: 0, Stdout: outB.String(), Stderr: errB.String()}
	if runErr != nil {
		if ee, ok := runErr.(*ssh.ExitError); ok {
			res.Exit = ee.ExitStatus()
		} else {
			return res, fmt.Errorf("sy: exec: %v", runErr)
		}
	}
	return res, nil
}

// hostKeySHA256 renders a connected host key for TOTFU-style display.
func hostKeySHA256(k ssh.PublicKey) string {
	sum := sha256.Sum256(k.Marshal())
	return "SHA256:" + base64.StdEncoding.EncodeToString(sum[:])
}

// portOf extracts the port of an address string for error messages.
func portOf(addr string) string {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return strconv.Itoa(22)
	}
	return p
}
