#!/bin/sh
# Installs winch from its GitHub release:
#
#   curl -fsSL https://winchstack.app/install.sh | sh
#
# WINCH_VERSION names a release, such as v0.2.0-rc.1; without it, the
# script installs the newest release. WINCH_INSTALL_DIR replaces the
# directory ~/.local/bin.

set -eu

fail() {
	echo "install.sh: $*" >&2
	exit 1
}

# The whole script is read before main runs, so a cut download runs nothing.
main() {
	os=$(uname -s)
	arch=$(uname -m)
	case $os/$arch in
	Darwin/arm64) platform=darwin-arm64 ;;
	Darwin/x86_64) platform=darwin-amd64 ;;
	Linux/x86_64) platform=linux-amd64 ;;
	Linux/aarch64 | Linux/arm64) platform=linux-arm64 ;;
	*) fail "winch has no build for $os $arch; it runs on macOS and Linux, on amd64 and arm64" ;;
	esac
	if command -v sha256sum >/dev/null; then
		sha256=sha256sum
	elif command -v shasum >/dev/null; then
		sha256="shasum -a 256"
	else
		fail "needs sha256sum or shasum to check the download"
	fi

	url=https://github.com/davidklassen/winch/releases/latest/download
	hint=
	if [ -n "${WINCH_VERSION:-}" ]; then
		url=https://github.com/davidklassen/winch/releases/download/$WINCH_VERSION
		hint="; check WINCH_VERSION"
	fi
	if [ -z "${WINCH_INSTALL_DIR:-}" ] && [ -z "${HOME:-}" ]; then
		fail "HOME is not set; set WINCH_INSTALL_DIR to the directory for winch"
	fi
	dir=${WINCH_INSTALL_DIR:-$HOME/.local/bin}
	archive=winch-$platform.tar.gz

	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	# dash runs the EXIT trap on exit, not on a signal.
	trap 'exit 1' HUP INT TERM
	curl -fsSL -o "$tmp/$archive" "$url/$archive" || fail "cannot download $url/$archive$hint"
	curl -fsSL -o "$tmp/checksums.txt" "$url/checksums.txt" || fail "cannot download $url/checksums.txt$hint"
	want=$(awk -v name="$archive" '$2 == name { print $1 }' "$tmp/checksums.txt")
	[ -n "$want" ] || fail "checksums.txt has no line for $archive; nothing is installed"
	[ "$($sha256 "$tmp/$archive" | cut -d ' ' -f 1)" = "$want" ] ||
		fail "the SHA-256 of $archive is not the one in checksums.txt; nothing is installed"

	tar -xzf "$tmp/$archive" -C "$tmp" winch
	mkdir -p "$dir"
	# A move in one directory replaces a running winch without a gap.
	cp "$tmp/winch" "$dir/.winch.new"
	chmod 755 "$dir/.winch.new"
	mv -f "$dir/.winch.new" "$dir/winch"
	echo "installed $dir/winch"
	"$dir/winch" version || fail "$dir/winch does not run"

	case :$PATH: in
	*:"$dir":*) ;;
	*) printf '%s is not in PATH; add it with:\nexport PATH="%s:$PATH"\n' "$dir" "$dir" ;;
	esac
}

main
