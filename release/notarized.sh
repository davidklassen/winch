#!/bin/sh
# Prints "accepted" or "in progress" for the macOS archives of a release:
# notarized.sh <checksums.txt> <history.json>. The history is the JSON
# output of notarytool history. The release workflow names each
# submission winch-darwin-<arch>-<SHA-256 of the archive>.zip.

set -eu

state=accepted
for p in darwin-arm64 darwin-amd64; do
	sha=$(awk -v name="winch-$p.tar.gz" '$2 == name { print $1 }' "$1")
	[ -n "$sha" ] || {
		echo "notarized.sh: $1 has no line for winch-$p.tar.gz" >&2
		exit 1
	}
	name=winch-$p-$sha.zip
	sub=$(jq -r --arg name "$name" '
		[.history[] | select(.name == $name)] | sort_by(.createdDate) | last
		| if . then [.status, .id] | @tsv else empty end
	' "$2")
	case $sub in
	'')
		echo "notarized.sh: $2 has no submission $name" >&2
		exit 1
		;;
	"Accepted	"*) ;;
	"In Progress	"*) state="in progress" ;;
	*)
		echo "notarized.sh: Apple did not accept winch-$p.tar.gz: status ${sub%	*}, submission ${sub#*	}" >&2
		exit 1
		;;
	esac
done
echo "$state"
