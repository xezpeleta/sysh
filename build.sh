#!/bin/bash
# Build the sysh .deb (§14.5). Static Go binary, dpkg-deb packaging.
set -eu

cd "$(dirname "$0")"

VERSION=${VERSION:-0.6.1}
OUT=dist
STAGE=$OUT/sysh-$VERSION

rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" \
         "$STAGE/usr/bin" \
         "$STAGE/usr/lib/tmpfiles.d" \
         "$STAGE/usr/share/sysh" \
         "$STAGE/usr/share/doc/sysh"

# --- binary (static, stripped, reproducible-ish)
CGO_ENABLED=0 GOFLAGS=-trimpath go build \
  -ldflags "-s -w -X github.com/xezpeleta/sysh/internal/control.Version=$VERSION" \
  -o "$STAGE/usr/bin/sysh" ./cmd/sysh
chmod 0755 "$STAGE/usr/bin/sysh"

# sy: the agent-side client (MCP surface) — operator machines install
# it too; on hosts it is inert (a client, not a server component).
CGO_ENABLED=0 GOFLAGS=-trimpath go build \
  -ldflags "-s -w -X main.version=$VERSION" \
  -o "$STAGE/usr/bin/sy" ./cmd/sy
chmod 0755 "$STAGE/usr/bin/sy"

# --- control files
sed "s/__VERSION__/$VERSION/" debian/control > "$STAGE/DEBIAN/control"
install -m 0755 debian/postinst "$STAGE/DEBIAN/postinst"
install -m 0755 debian/postrm   "$STAGE/DEBIAN/postrm"

# --- payload
install -m 0644 debian/tmpfiles/sysh.conf "$STAGE/usr/lib/tmpfiles.d/sysh.conf"
install -m 0644 debian/sshd/60-sysh.conf  "$STAGE/usr/share/sysh/sshd-dropin.conf"
install -m 0644 debian/audit/60-sysh.rules "$STAGE/usr/share/sysh/audit-rules.template"
install -m 0644 testdata/policy.example.toml "$STAGE/usr/share/sysh/policy.example.toml"
install -m 0644 LICENSE "$STAGE/usr/share/doc/sysh/copyright" 2>/dev/null || true
install -m 0644 README.md "$STAGE/usr/share/doc/sysh/README.md" 2>/dev/null || true
gzip -9n < debian/changelog > "$STAGE/usr/share/doc/sysh/changelog.gz" 2>/dev/null || true

# --- permissions: root-owned everywhere; the deb is installed by root
dpkg-deb --root-owner-group --build "$STAGE" "$OUT/sysh_${VERSION}_amd64.deb"

echo "built $OUT/sysh_${VERSION}_amd64.deb"
