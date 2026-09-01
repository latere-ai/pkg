#!/bin/sh
# release-notes.sh TAG [REF]
#
# Prints the CHANGELOG.md section for TAG, read from REF (default: the working
# tree), and exits 1 when the section is missing or empty. The release
# workflow uses it to refuse a tag without a note and to build the GitHub
# release body; the pre-push hook uses it to refuse the push in the first
# place; make release uses it to check its own work.
set -eu

tag=$1
ref=${2:-}

if [ -n "$ref" ]; then
	changelog=$(git show "$ref:CHANGELOG.md" 2>/dev/null) || { echo "no CHANGELOG.md at $ref" >&2; exit 1; }
else
	changelog=$(cat CHANGELOG.md)
fi

# The section runs from its "## <tag>" heading to the next "## " heading.
section=$(printf '%s\n' "$changelog" | awk -v tag="$tag" '
	/^## / { if (found) exit; if ($2 == tag) { found = 1; next } }
	found { print }
')

if [ -z "$(printf '%s' "$section" | tr -d '[:space:]')" ]; then
	echo "CHANGELOG.md has no section for $tag" >&2
	echo "add '## $tag - YYYY-MM-DD' with the notes, or run: make release VERSION=$tag" >&2
	exit 1
fi
printf '%s\n' "$section"
