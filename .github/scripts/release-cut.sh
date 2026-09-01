#!/bin/sh
# release-cut.sh VERSION
#
# Moves what sits under "## Unreleased" in CHANGELOG.md into a section for
# VERSION, commits, tags, and pushes main and the tag. The release workflow
# then publishes the GitHub release from that section. An empty Unreleased
# section stops here: a tag is a release, and a release has notes.
set -eu

version=${1:-}
case "$version" in
v[0-9]*.[0-9]*.[0-9]*) ;;
*) echo "usage: release-cut.sh vX.Y.Z" >&2; exit 1 ;;
esac

here=$(dirname "$0")
[ -z "$(git status --porcelain)" ] || { echo "release: the working tree is not clean" >&2; exit 1; }
! git rev-parse -q --verify "refs/tags/$version" >/dev/null || { echo "release: $version already exists" >&2; exit 1; }
"$here/release-notes.sh" Unreleased >/dev/null 2>&1 || { echo "release: nothing under '## Unreleased' in CHANGELOG.md" >&2; exit 1; }

today=$(date +%Y-%m-%d)
awk -v v="$version" -v d="$today" '
	/^## Unreleased$/ && !done { print; print ""; print "## " v " - " d; done = 1; next }
	{ print }
' CHANGELOG.md > CHANGELOG.md.new
mv CHANGELOG.md.new CHANGELOG.md
"$here/release-notes.sh" "$version" >/dev/null

git add CHANGELOG.md
git commit -m "changelog: $version"
git tag -a "$version" -m "$version"
git push origin main "$version"
