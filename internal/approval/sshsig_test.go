package approval

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/ssh"
)

// newTestSigner makes a real ed25519 SSH signer (no fixtures on disk).
func newTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// buildSSHSig builds a full SSHSIG blob (and armor) for a signature the
// given signer produces over the frame of (namespace, hashAlg, body).
func buildSSHSig(t *testing.T, signer ssh.Signer, namespace, hashAlg string, body []byte) []byte {
	t.Helper()
	frame := sshsigFrame(namespace, hashAlg, body)
	sig, err := signer.Sign(rand.Reader, frame)
	if err != nil {
		t.Fatal(err)
	}
	var wire []byte
	wire = appendStr(wire, []byte(sig.Format))
	wire = appendStr(wire, sig.Blob)
	wire = append(wire, sig.Rest...)

	var blob []byte
	blob = append(blob, sshsigMagic...)
	blob = appendU32(blob, sshsigVersion)
	blob = appendStr(blob, signer.PublicKey().Marshal())
	blob = appendStr(blob, []byte(namespace))
	blob = appendStr(blob, nil)
	blob = appendStr(blob, []byte(hashAlg))
	blob = appendStr(blob, wire)
	return armorSSH(blob)
}

// sshsigFrame is the signed structure: magic || ns || reserved || hashalg || H(body).
func sshsigFrame(namespace, hashAlg string, body []byte) []byte {
	var f bytes.Buffer
	f.WriteString(sshsigMagic)
	sshsigPutString(&f, []byte(namespace))
	sshsigPutString(&f, nil)
	sshsigPutString(&f, []byte(hashAlg))
	digest := sha512.Sum512(body)
	sshsigPutString(&f, digest[:])
	return f.Bytes()
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendStr(b, s []byte) []byte {
	b = appendU32(b, uint32(len(s)))
	return append(b, s...)
}

func armorSSH(blob []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(blob)
	var out bytes.Buffer
	out.WriteString("-----BEGIN SSH SIGNATURE-----\n")
	for len(enc) > 72 {
		out.WriteString(enc[:72] + "\n")
		enc = enc[72:]
	}
	if enc != "" {
		out.WriteString(enc + "\n")
	}
	out.WriteString("-----END SSH SIGNATURE-----\n")
	return out.Bytes()
}

func TestParseAndVerifyRoundtrip(t *testing.T) {
	signer := newTestSigner(t)
	body := []byte(`{"id":"req_0123456789ab","argv":["/usr/bin/touch","/tmp/x"]}`)

	sig, err := ParseSSHSig(buildSSHSig(t, signer, "sysh-approve", SSHSigHashAlg, body))
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Verify(body, "sysh-approve"); err != nil {
		t.Fatal(err)
	}

	// different content: must fail
	if err := sig.Verify([]byte(`{"id":"req_0123456789ab","argv":["/usr/bin/touch","/tmp/y"]}`), "sysh-approve"); err == nil {
		t.Fatal("signature over different content must not verify")
	}
	// different namespace: must fail
	if err := sig.Verify(body, "git"); err == nil {
		t.Fatal("signature under wrong namespace must not verify")
	}
}

func TestParseSSHSigRefusals(t *testing.T) {
	signer := newTestSigner(t)
	body := []byte("content")
	goodRaw, err := sshsigDearmor(buildSSHSig(t, signer, "ns", SSHSigHashAlg, body))
	if err != nil {
		t.Fatal(err)
	}

	// a structurally complete blob with each field corrupted
	blob := func(f func(b []byte) []byte) []byte { return armorSSH(f(append([]byte{}, goodRaw...))) }

	cases := map[string][]byte{
		"not armor":          []byte("hello"),
		"bad base64":         []byte("-----BEGIN SSH SIGNATURE-----\n!!!!\n-----END SSH SIGNATURE-----"),
		"no begin marker":    []byte("QUNBQg=="),
		"truncated magic":    armorSSH([]byte("SSH")),
		"truncated version":  armorSSH([]byte("SSHSIG\x00\x00")),
		"empty":              armorSSH(nil),
		"unknown version":    blob(func(b []byte) []byte { b[7] = 9; return b }),
		"trailing bytes":     blob(func(b []byte) []byte { return append(b, 0) }),
		"truncated tail":     blob(func(b []byte) []byte { return b[:len(b)-1] }),
		"garbage pubkey":     blob(func(b []byte) []byte { b[10] ^= 0xff; return b }),
	}
	for name, in := range cases {
		if _, err := ParseSSHSig(in); err == nil {
			t.Errorf("%s: accepted garbage", name)
		}
	}

	// a corrupted signature parses structurally (string lengths hold)
	// but must fail at Verify — the crypto boundary
	corruptSig := blob(func(b []byte) []byte { b[len(b)-3] ^= 0xff; return b })
	cparsed, err := ParseSSHSig(corruptSig)
	if err != nil {
		t.Fatal("corrupted sig should still parse:", err)
	}
	if err := cparsed.Verify(body, "ns"); err == nil {
		t.Error("corrupted signature must not verify")
	}

	// structurally valid but wrong semantics
	parsed, err := ParseSSHSig(armorSSH(goodRaw))
	if err != nil {
		t.Fatal(err)
	}
	nonReserved := buildRaw(t, parsed.PublicKey.Marshal(), "ns", "x", SSHSigHashAlg, lastWire(t, goodRaw))
	if _, err := ParseSSHSig(armorSSH(nonReserved)); err == nil {
		t.Error("non-empty reserved field must be refused")
	}
	wrongHash := buildRaw(t, parsed.PublicKey.Marshal(), "ns", "", "sha256", lastWire(t, goodRaw))
	if _, err := ParseSSHSig(armorSSH(wrongHash)); err == nil {
		t.Error("unsupported hash algorithm must be refused")
	}
}

func buildRaw(t *testing.T, pub []byte, ns, reserved, hash string, sig []byte) []byte {
	t.Helper()
	var b []byte
	b = append(b, sshsigMagic...)
	b = appendU32(b, sshsigVersion)
	b = appendStr(b, pub)
	b = appendStr(b, []byte(ns))
	b = appendStr(b, []byte(reserved))
	b = appendStr(b, []byte(hash))
	b = appendStr(b, sig)
	return b
}

// lastWire extracts the trailing signature string from a parsed blob.
func lastWire(t *testing.T, raw []byte) []byte {
	t.Helper()
	_, err := ParseSSHSig(armorSSH(raw))
	if err != nil {
		t.Fatal(err)
	}
	// walk to the last string field
	b := raw[len(sshsigMagic):]
	_, b, _ = sshsigUint32(b) // version
	_, b, _ = sshsigString(b) // pubkey
	_, b, _ = sshsigString(b) // ns
	_, b, _ = sshsigString(b) // reserved
	_, b, _ = sshsigString(b) // hashalg
	sig, _, err := sshsigString(b)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}
