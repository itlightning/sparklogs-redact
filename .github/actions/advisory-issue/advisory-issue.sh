#!/usr/bin/env bash
# Shared template, copied unchanged into several repositories. Do not edit this copy.
# ci-advisory-issue template v1
#
# Records the result of a dependency advisory check as a GitHub issue: a failed scan
# opens one issue with the label (or comments on the oldest open one), a passed scan
# comments on and closes every open issue with the label. A cancelled or skipped scan
# proved nothing, so it changes nothing and exits non-zero. Pull request events are
# refused, so a caller without the job condition cannot write issues from one.
#
# Environment (the composite action sets the first four; GitHub Actions sets the rest):
#   ADVISORY_ISSUE_RESULT      the scan job's result: success, failure, cancelled, skipped
#   ADVISORY_ISSUE_FINDINGS    finding ids separated by whitespace, may be empty;
#                              untrusted text, reaches gh only through a body file
#   ADVISORY_ISSUE_LABEL       label that marks the issue (default dependency-advisory)
#   ADVISORY_ISSUE_CHECK_NAME  title text (default "Dependency advisory check")
#   GITHUB_EVENT_NAME, GITHUB_REPOSITORY, GITHUB_REF, GITHUB_SHA, GITHUB_SERVER_URL,
#   GITHUB_RUN_ID
#   GH                         gh binary (default gh); GH_TOKEN needs issues: write
#                              (labels and issues) and metadata read (default branch)
#
# A push run records only for the default branch: a feature branch push must not
# close the default branch's issue. Any gh failure fails the step, naming the command.

set -euo pipefail

GH="${GH:-gh}"
RESULT="${ADVISORY_ISSUE_RESULT:-}"
FINDINGS="${ADVISORY_ISSUE_FINDINGS:-}"
LABEL="${ADVISORY_ISSUE_LABEL:-dependency-advisory}"
CHECK_NAME="${ADVISORY_ISSUE_CHECK_NAME:-Dependency advisory check}"
LABEL_COLOR="b60205"
ISSUE_LIMIT=1000

die() {
  echo "::error::advisory-issue: $1" >&2
  exit 1
}

# gh_run <what> <args...>: runs gh; on failure names <what> (never the arguments,
# which can carry untrusted text) and fails the step.
gh_run() {
  local what="$1"
  shift
  "${GH}" "$@" || die "gh ${what} failed; the advisory result was not recorded"
}

require_env() {
  local name
  for name in "$@"; do
    [[ -n "${!name:-}" ]] || die "${name} is not set"
  done
}

# Label names matching the label. Call it as an assignment, never inside a condition:
# set -e does not apply there, and a failed lookup would read as "no label".
label_names() {
  gh_run "label list" label list -R "${GITHUB_REPOSITORY}" --search "${LABEL}" --limit 100 --json name --jq '.[].name'
}

has_label() {
  grep -qxF -- "${LABEL}" <<<"$1"
}

ensure_label() {
  local names
  names="$(label_names)"
  has_label "${names}" && return 0
  gh_run "label create" label create "${LABEL}" -R "${GITHUB_REPOSITORY}" \
    --color "${LABEL_COLOR}" --description "${CHECK_NAME} is failing"
  echo "created label ${LABEL}"
}

# Open issue numbers with the label, oldest (lowest number) first.
open_issues() {
  gh_run "issue list" issue list -R "${GITHUB_REPOSITORY}" --label "${LABEL}" --state open \
    --limit "${ISSUE_LIMIT}" --json number --jq 'sort_by(.number) | .[].number'
}

# write_body <file> <headline>: the facts of this run. Finding ids go in an indented
# code block, so no id can render as markup or mention anyone.
write_body() {
  local file="$1" headline="$2" ids=()
  read -r -d '' -a ids <<<"${FINDINGS}" || true
  {
    echo "${headline}"
    echo ""
    echo "- Run: ${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
    echo "- Commit: ${GITHUB_SHA}"
    echo "- Event: ${GITHUB_EVENT_NAME} on ${GITHUB_REF}"
    if [[ "${#ids[@]}" -gt 0 ]]; then
      echo "- Finding ids:"
      echo ""
      printf '    %s\n' "${ids[@]}"
    else
      echo "- Finding ids: none printed (the scan failed without a finding, for example an unreachable registry; see the run)"
    fi
  } >"${file}"
}

record_failure() {
  local default_branch="$1" body issues oldest
  body="$(mktemp)"
  ensure_label
  issues="$(open_issues)"
  if [[ -z "${issues}" ]]; then
    write_body "${body}" "The ${CHECK_NAME} failed."
    gh_run "issue create" issue create -R "${GITHUB_REPOSITORY}" \
      --title "${CHECK_NAME} is failing on ${default_branch}" --label "${LABEL}" --body-file "${body}"
  else
    oldest="$(head -n 1 <<<"${issues}")"
    write_body "${body}" "The ${CHECK_NAME} failed again."
    gh_run "issue comment ${oldest}" issue comment "${oldest}" -R "${GITHUB_REPOSITORY}" --body-file "${body}"
    echo "commented on issue ${oldest}"
  fi
  rm -f "${body}"
}

record_success() {
  local body issues n names
  names="$(label_names)"
  if ! has_label "${names}"; then
    echo "no label ${LABEL}, so no open issue to close"
    return 0
  fi
  issues="$(open_issues)"
  if [[ -z "${issues}" ]]; then
    echo "no open issue labeled ${LABEL}"
    return 0
  fi
  body="$(mktemp)"
  {
    echo "The ${CHECK_NAME} passed; closing."
    echo ""
    echo "- Run: ${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
    echo "- Commit: ${GITHUB_SHA}"
  } >"${body}"
  while read -r n; do
    gh_run "issue comment ${n}" issue comment "${n}" -R "${GITHUB_REPOSITORY}" --body-file "${body}"
    gh_run "issue close ${n}" issue close "${n}" -R "${GITHUB_REPOSITORY}" --reason completed
    echo "closed issue ${n}"
  done <<<"${issues}"
  rm -f "${body}"
}

main() {
  local default_branch
  require_env GITHUB_EVENT_NAME GITHUB_REPOSITORY GITHUB_REF GITHUB_SHA GITHUB_SERVER_URL GITHUB_RUN_ID
  case "${GITHUB_EVENT_NAME}" in
    pull_request*) die "refusing to run on ${GITHUB_EVENT_NAME}: pull request runs never read or write issues (give the job if: github.event_name != 'pull_request')" ;;
  esac
  case "${RESULT}" in
    success | failure) ;;
    cancelled | skipped) die "the scan job was ${RESULT}: it proved nothing, so nothing was recorded" ;;
    *) die "unknown scan result '${RESULT}' (want success, failure, cancelled or skipped)" ;;
  esac
  # PROVENANCE: REST "Get a repository" (GET /repos/{owner}/{repo}) returns default_branch
  # (docs.github.com REST repos reference). The schedule event has no webhook payload per
  # docs.github.com "Events that trigger workflows" (read 2026-11-25), so the default
  # branch is read here rather than from github.event.repository.
  default_branch="$(gh_run "api repos/${GITHUB_REPOSITORY}" api "repos/${GITHUB_REPOSITORY}" --jq .default_branch)"
  [[ -n "${default_branch}" ]] || die "gh api returned no default branch"
  if [[ "${GITHUB_EVENT_NAME}" == "push" && "${GITHUB_REF}" != "refs/heads/${default_branch}" ]]; then
    die "refusing to record a push to ${GITHUB_REF}: only the default branch (${default_branch}) is recorded"
  fi
  if [[ "${RESULT}" == "failure" ]]; then
    record_failure "${default_branch}"
  else
    record_success
  fi
}

main "$@"
