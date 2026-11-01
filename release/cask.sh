#!/bin/sh
# Prints the Homebrew cask of a release: cask.sh <tag> <checksums.txt>.

set -eu

sum() {
	sha=$(awk -v name="winch-$1.tar.gz" '$2 == name { print $1 }' "$2")
	[ -n "$sha" ] || {
		echo "cask.sh: $2 has no line for winch-$1.tar.gz" >&2
		exit 1
	}
	echo "$sha"
}

arm=$(sum darwin-arm64 "$2")
intel=$(sum darwin-amd64 "$2")
cat <<CASK
cask "winch" do
  arch arm: "arm64", intel: "amd64"

  version "${1#v}"
  sha256 arm:   "$arm",
         intel: "$intel"

  url "https://github.com/davidklassen/winch/releases/download/v#{version}/winch-darwin-#{arch}.tar.gz"
  name "winch"
  desc "Server configuration tool"
  homepage "https://winchstack.app/"

  depends_on macos: :ventura

  binary "winch"
end
CASK
