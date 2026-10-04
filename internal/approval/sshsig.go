// SSHSIG, the OpenSSH file-signature format (PROTOCOL.sshsig), parsed
// and verified in-process with x/crypto/ssh. No subprocess and no
// dependency on the local ssh-keygen build's `-Y verify` — the
// operator still signs with stock `ssh-keygen -Y sign` (or any SSHSIG
// producer), the server verifies the bytes itself.
//
// Blob layout (base64 inside a PEM-ish "SSH SIGNATURE" armor):
//
//	byte[6]  magic "SSHSIG"
//	uint32   version (1)
//	string   publickey   (SSH wire key blob — ssh.ParsePublicKey input)
//	string   namespace   (protocol binding; ours is "sysh-approve")
//	string   reserved    (must be empty)
//	string   hash_algorithm ("sha512")
//	string   signature   (SSH wire signature: string format, string
//	                      blob, then sk flags/counter for FIDO2 keys)
//
// The signature covers: "SSHSIG" || string ns || string reserved ||
// string hash_algorithm || string H(body), with H the named hash.
package approval

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	sshsigMagic      = "SSHSIG"
	sshsigVersion    = 1
	SSHSigHashAlg    = "sha512"
	sshsigArmorBegin = "-----BEGIN SSH SIGNATURE-----"
)

// SSHSig is a parsed (not yet verified) SSHSIG blob.
type SSHSig struct {
	PublicKey ssh.PublicKey // embedded signer key
	Namespace string
	Reserved  string
	HashAlg   string
	Sig       *ssh.Signature
}

// ParseSSHSig decodes the armored blob and parses its fields. It does
// not verify the signature (see Verify) but does refuse structural
// garbage: bad armor, wrong magic, unknown version, non-empty
// reserved field, or a hash algorithm other than sha512.
func ParseSSHSig(armored []byte) (SSHSig, error) {
	raw, err := sshsigDearmor(armored)
	if err != nil {
		return SSHSig{}, err
	}
	b := raw
	if !bytes.HasPrefix(b, []byte(sshsigMagic)) {
		return SSHSig{}, fmt.Errorf("not an SSHSIG blob (bad magic)")
	}
	b = b[len(sshsigMagic):]
	ver, b, err := sshsigUint32(b)
	if err != nil {
		return SSHSig{}, err
	}
	if ver != sshsigVersion {
		return SSHSig{}, fmt.Errorf("unsupported SSHSIG version %d", ver)
	}
	pubWire, b, err := sshsigString(b)
	if err != nil {
		return SSHSig{}, err
	}
	ns, b, err := sshsigString(b)
	if err != nil {
		return SSHSig{}, err
	}
	reserved, b, err := sshsigString(b)
	if err != nil {
		return SSHSig{}, err
	}
	hashAlg, b, err := sshsigString(b)
	if err != nil {
		return SSHSig{}, err
	}
	sigWire, b, err := sshsigString(b)
	if err != nil {
		return SSHSig{}, err
	}
	if len(b) != 0 {
		return SSHSig{}, fmt.Errorf("trailing bytes after SSHSIG fields")
	}
	if len(reserved) != 0 {
		return SSHSig{}, fmt.Errorf("SSHSIG reserved field not empty")
	}
	if string(hashAlg) != SSHSigHashAlg {
		return SSHSig{}, fmt.Errorf("SSHSIG hash algorithm %q not supported (want %s)", hashAlg, SSHSigHashAlg)
	}
	key, err := ssh.ParsePublicKey(pubWire)
	if err != nil {
		return SSHSig{}, fmt.Errorf("SSHSIG embedded public key: %v", err)
	}
	sig, err := parseWireSignature(sigWire)
	if err != nil {
		return SSHSig{}, err
	}
	return SSHSig{
		PublicKey: key,
		Namespace: string(ns),
		Reserved:  string(reserved),
		HashAlg:   string(hashAlg),
		Sig:       sig,
	}, nil
}

// Verify checks the signature over body under the expected namespace
// (protocol binding: a signature made for any other namespace fails).
// FIDO2 (sk-*) keys verify through x/crypto/ssh with their flags and
// counter — the touch happened on the token at sign time.
func (s SSHSig) Verify(body []byte, wantNamespace string) error {
	if s.Namespace != wantNamespace {
		return fmt.Errorf("signature namespace is %q, want %q", s.Namespace, wantNamespace)
	}
	// The signed frame: magic || ns || reserved || hashalg || H(body).
	var frame bytes.Buffer
	frame.WriteString(sshsigMagic)
	sshsigPutString(&frame, []byte(s.Namespace))
	sshsigPutString(&frame, []byte(s.Reserved))
	sshsigPutString(&frame, []byte(s.HashAlg))
	digest := sha512.Sum512(body)
	sshsigPutString(&frame, digest[:])
	return s.PublicKey.Verify(frame.Bytes(), s.Sig)
}

// parseWireSignature parses the SSH wire signature exactly as
// x/crypto/ssh does (string format, string blob, then sk fields for
// hardware-backed keys) so PublicKey.Verify sees what it expects.
func parseWireSignature(in []byte) (*ssh.Signature, error) {
	format, rest, err := sshsigString(in)
	if err != nil {
		return nil, err
	}
	blob, rest, err := sshsigString(rest)
	if err != nil {
		return nil, err
	}
	sig := &ssh.Signature{Format: string(format), Blob: blob, Rest: rest}
	return sig, nil
}

// sshsigDearmor strips the "-----BEGIN/END SSH SIGNATURE-----" frame
// and decodes the base64 body (whitespace-tolerant).
func sshsigDearmor(armored []byte) ([]byte, error) {
	s := string(armored)
	begin := strings.Index(s, sshsigArmorBegin)
	if begin < 0 {
		return nil, fmt.Errorf("not an ssh-keygen signature (expected %s)", sshsigArmorBegin)
	}
	s = s[begin+len(sshsigArmorBegin):]
	if end := strings.Index(s, "-----END"); end >= 0 {
		s = s[:end]
	}
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	return base64.StdEncoding.DecodeString(s)
}

// Minimal bounded ssh wire readers (string / uint32) — shared with
// nothing, deliberately: SSHSIG parsing is small and self-contained.

func sshsigString(b []byte) (val, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, fmt.Errorf("sshsig: truncated string header")
	}
	n := int(uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]))
	b = b[4:]
	if n < 0 || len(b) < n {
		return nil, nil, fmt.Errorf("sshsig: truncated string body")
	}
	return b[:n], b[n:], nil
}

func sshsigUint32(b []byte) (val uint32, rest []byte, err error) {
	if len(b) < 4 {
		return 0, nil, fmt.Errorf("sshsig: truncated uint32")
	}
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return v, b[4:], nil
}

func sshsigPutString(buf *bytes.Buffer, v []byte) {
	var l [4]byte
	l[0] = byte(len(v) >> 24)
	l[1] = byte(len(v) >> 16)
	l[2] = byte(len(v) >> 8)
	l[3] = byte(len(v))
	buf.Write(l[:])
	buf.Write(v)
}
