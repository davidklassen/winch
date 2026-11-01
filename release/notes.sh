#!/bin/sh
# Prints the section of a tag in the changelog: notes.sh <tag> <changelog>.
# A pre-release such as v0.2.0-rc.1 takes the section of v0.2.0.

set -eu

[ -f "$2" ] || {
	echo "notes.sh: $2 does not exist" >&2
	exit 1
}
version=${1%%-*}
notes=$(awk -v head="## $version" '
	$0 == head { found = 1; next }
	found && /^## / { exit }
	found { print }
' "$2")
[ -n "$notes" ] || {
	echo "notes.sh: $2 has no section ## $version" >&2
	exit 1
}
# The command substitution drops the blank lines at the end.
printf '%s\n' "$notes" | sed '/./,$!d'
