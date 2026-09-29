#!/usr/bin/env bash
set -uo pipefail
# Report known vulnerabilities that kubescape's own code can actually reach.
#
# govulncheck matches the module graph against the Go vulnerability database
# and then walks the call graph, so a finding here means a vulnerable function
# is reachable from kubescape - not merely that a vulnerable module is
# somewhere in go.sum. That keeps the signal low-noise enough to show on every
# PR.
#
# Findings are reported, not enforced, unless GOVULNCHECK_FAIL_ON_FINDINGS is
# "true": several reachable vulnerabilities currently have no fixed release
# (claircore, docker/docker, x/crypto/openpgp), so a blocking check would stay
# red on every PR until those are dealt with. When enforcing, the step exits
# with govulncheck's own "vulnerabilities found" status, 3. A failure of the
# tool itself (bad install, unreachable vulnerability database, a package that
# does not build, a report this script cannot read) always fails the step, so
# a green result never means "did not run".
#
# The Go toolchain matters: standard-library findings are reported against the
# toolchain running this script. CI runs it on the same Go line the release
# workflow builds with, so those findings describe what actually ships.

# Pinned so a new govulncheck release cannot change this check's behaviour
# without a reviewed change here. Bump deliberately.
GOVULNCHECK_VERSION="v1.8.0"

report="$(mktemp)"
bindir="$(mktemp -d)"
trap 'rm -rf "$report" "$bindir"' EXIT

# summary appends the outcome and the full report to the job summary, when the
# step runs in GitHub Actions.
summary() {
    [ -n "${GITHUB_STEP_SUMMARY:-}" ] || return 0
    {
        echo "## govulncheck ${GOVULNCHECK_VERSION}"
        echo
        echo "$1"
        echo
        echo '```'
        cat "$report"
        echo '```'
    } >>"$GITHUB_STEP_SUMMARY"
}

# Installed and then executed, not `go run`: go run reports any non-zero exit
# of the program as its own exit status 1, which would erase the distinction
# between "found vulnerabilities" (3) and "could not scan" below.
if ! GOBIN="$bindir" go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"; then
    echo "::error title=govulncheck::could not install govulncheck ${GOVULNCHECK_VERSION}"
    exit 1
fi

"$bindir/govulncheck" ./... >"$report" 2>&1
rc=$?

cat "$report"

# govulncheck exits 3 when it found reachable vulnerabilities and 0 when it
# found none; anything else means it could not complete the scan.
case "$rc" in
0)
    summary "No reachable vulnerabilities found."
    exit 0
    ;;
3) ;;
*)
    echo "::error title=govulncheck::govulncheck ${GOVULNCHECK_VERSION} failed with exit code ${rc}; see the log above"
    summary "The scan did not complete (exit code ${rc})."
    exit "$rc"
    ;;
esac

# One annotation per reachable vulnerability, so each one shows on the PR's
# checks page without opening the log. The report pairs a
# "Vulnerability #N: GO-YYYY-NNNN" line with an indented title (wrapped over
# as many lines as it needs, ending at "More info:") and, per affected module,
# "Found in:" / "Fixed in:" lines. "Fixed in: N/A" means there is no fix yet.
# The message is escaped as workflow commands require.
annotations="$(awk '
    function esc(s) { gsub(/%/, "%25", s); gsub(/\r/, "%0D", s); return s }
    function flush() {
        if (id == "") return
        msg = title
        msg = msg (fix == "" ? " (no fixed version yet)" : " (fixed in: " fix ")")
        printf "::warning title=govulncheck %s::%s https://pkg.go.dev/vuln/%s\n", id, esc(msg), id
    }
    /^Vulnerability #[0-9]+: / { flush(); id = $3; title = ""; fix = ""; intitle = 1; next }
    intitle && /^  More info: / { intitle = 0; next }
    intitle && /^    [^ ]/ { t = substr($0, 5); title = (title == "" ? t : title " " t); next }
    id != "" && /^    Fixed in: / {
        f = substr($0, 15)
        if (f != "N/A") fix = (fix == "" ? f : fix ", " f)
        next
    }
    END { flush() }
' "$report")"

if [ -z "$annotations" ]; then
    # Exit code 3 promises findings. Reporting none would make a changed report
    # format look like a clean scan.
    echo "::error title=govulncheck::govulncheck ${GOVULNCHECK_VERSION} reported vulnerabilities, but none could be read from its report"
    summary "Vulnerabilities were reported, but the report could not be read."
    exit 1
fi
echo "$annotations"
count="$(printf '%s\n' "$annotations" | grep -c '^::warning ')"

if [ "${GOVULNCHECK_FAIL_ON_FINDINGS:-false}" = "true" ]; then
    summary "${count} reachable vulnerabilities found. GOVULNCHECK_FAIL_ON_FINDINGS is true, so this step fails."
    exit "$rc"
fi
summary "${count} reachable vulnerabilities found. They are reported, not enforced; set GOVULNCHECK_FAIL_ON_FINDINGS=true to fail on findings."
exit 0
