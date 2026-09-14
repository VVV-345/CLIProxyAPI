#!/usr/bin/env bash
set -euo pipefail

action="${1:?action is required}"
target_tag="${2:?target tag is required}"
request_id="${3:?request id is required}"
sync_branch="codex/upstream-sync"
artifact_dir="${RUNNER_TEMP:?RUNNER_TEMP is required}/upstream-sync"
status_path=".codex/upstream-sync-status.json"
review_path=".codex/upstream-sync-review.md"
workflow_url="https://github.com/${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}/actions/runs/${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"

if [[ ! "$target_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  printf 'Invalid upstream tag: %s\n' "$target_tag" >&2
  exit 2
fi
if [[ ! "$request_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
  printf 'Invalid request id\n' >&2
  exit 2
fi
if [[ "$action" != "analyze" && "$action" != "promote" ]]; then
  printf 'Invalid action: %s\n' "$action" >&2
  exit 2
fi

mkdir -p "$artifact_dir" .codex
git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git remote add upstream https://github.com/router-for-me/CLIProxyAPI.git 2>/dev/null || true
git fetch --force --no-tags upstream "refs/tags/${target_tag}:refs/tags/upstream-sync-target"
target_ref="refs/tags/upstream-sync-target"

write_report() {
  local state="$1"
  local message="$2"
  local base_sha="$3"
  local candidate_sha="$4"
  local conflict_file="$5"
  local failed_file="$6"
  SYNC_STATE="$state" \
  SYNC_MESSAGE="$message" \
  SYNC_BASE_SHA="$base_sha" \
  SYNC_CANDIDATE_SHA="$candidate_sha" \
  SYNC_CONFLICT_FILE="$conflict_file" \
  SYNC_FAILED_FILE="$failed_file" \
  SYNC_ACTION="$action" \
  SYNC_TARGET_TAG="$target_tag" \
  SYNC_REQUEST_ID="$request_id" \
  SYNC_WORKFLOW_URL="$workflow_url" \
  SYNC_STATUS_PATH="$status_path" \
  SYNC_REVIEW_PATH="$review_path" \
  python3 <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def lines(path: str) -> list[str]:
    candidate = Path(path)
    if not path or not candidate.exists():
        return []
    return [line.strip() for line in candidate.read_text(encoding="utf-8").splitlines() if line.strip()]


state = os.environ["SYNC_STATE"]
message = os.environ["SYNC_MESSAGE"]
base_sha = os.environ["SYNC_BASE_SHA"]
candidate_sha = os.environ["SYNC_CANDIDATE_SHA"] or None
conflicts = lines(os.environ["SYNC_CONFLICT_FILE"])
failed_steps = lines(os.environ["SYNC_FAILED_FILE"])
updated_at = datetime.now(timezone.utc).isoformat()
payload = {
    "schema_version": 1,
    "state": state,
    "action": os.environ["SYNC_ACTION"],
    "request_id": os.environ["SYNC_REQUEST_ID"],
    "target_tag": os.environ["SYNC_TARGET_TAG"],
    "base_sha": base_sha,
    "candidate_sha": candidate_sha,
    "conflict_files": conflicts,
    "failed_steps": failed_steps,
    "message": message,
    "workflow_url": os.environ["SYNC_WORKFLOW_URL"],
    "updated_at": updated_at,
}
Path(os.environ["SYNC_STATUS_PATH"]).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
conflict_text = "\n".join(f"- `{item}`" for item in conflicts) or "- None"
failed_text = "\n".join(f"- `{item}`" for item in failed_steps) or "- None"
review = f"""# Upstream Sync Review

## Result

- State: `{state}`
- Action: `{os.environ['SYNC_ACTION']}`
- Target upstream tag: `{os.environ['SYNC_TARGET_TAG']}`
- Fork base commit: `{base_sha}`
- Candidate code commit: `{candidate_sha or 'not created'}`
- Request ID: `{os.environ['SYNC_REQUEST_ID']}`
- Workflow: {os.environ['SYNC_WORKFLOW_URL']}
- Updated at: `{updated_at}`

{message}

## Conflicting files

{conflict_text}

## Failed validation steps

{failed_text}

## Codex instruction

Read `AGENTS.md` and `CODEX_UPSTREAM_SYNC.md`, stay on the fixed `codex/upstream-sync` branch, preserve all documented fork behavior, repair the conflicts or failures above, and rerun the complete Go test and build commands. Do not merge to `main` or deploy.
"""
Path(os.environ["SYNC_REVIEW_PATH"]).write_text(review, encoding="utf-8")
PY
  cp "$status_path" "$artifact_dir/upstream-sync-status.json"
  cp "$review_path" "$artifact_dir/upstream-sync-review.md"
}

commit_report() {
  local message="$1"
  git add "$status_path" "$review_path"
  if ! git diff --cached --quiet; then
    git commit -m "$message"
  fi
}

run_validation() {
  local failed_file="$1"
  local build_output="${RUNNER_TEMP}/cli-proxy-api"
  : >"$failed_file"
  set +e
  go test ./... >"$artifact_dir/go-test.log" 2>&1
  local test_code=$?
  go build -o "$build_output" ./cmd/server >"$artifact_dir/go-build.log" 2>&1
  local build_code=$?
  set -e
  rm -f "$build_output"
  if (( test_code != 0 )); then
    printf 'go test ./...\n' >>"$failed_file"
  fi
  if (( build_code != 0 )); then
    printf 'go build ./cmd/server\n' >>"$failed_file"
  fi
  [[ ! -s "$failed_file" ]]
}

bundle_branch() {
  git bundle create "$artifact_dir/candidate.bundle" "$sync_branch"
}

if [[ "$action" == "analyze" ]]; then
  base_sha="$(git rev-parse HEAD)"
  previous_status="$artifact_dir/previous-status.json"
  if git show "origin/${sync_branch}:${status_path}" >"$previous_status" 2>/dev/null; then
    previous_tag="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("target_tag") or "")' "$previous_status")"
    previous_base="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("base_sha") or "")' "$previous_status")"
  else
    previous_tag=""
    previous_base=""
  fi
  if [[ "$previous_tag" == "$target_tag" && "$previous_base" == "$base_sha" ]] \
    && git merge-base --is-ancestor origin/main "origin/${sync_branch}"; then
    git switch -C "$sync_branch" "origin/${sync_branch}"
  else
    git switch -C "$sync_branch" origin/main
  fi
  conflict_file="$artifact_dir/conflict-files.txt"
  failed_file="$artifact_dir/failed-steps.txt"
  merge_log="$artifact_dir/merge.log"
  : >"$conflict_file"
  : >"$failed_file"
  if ! git merge-base --is-ancestor "$target_ref" HEAD; then
    set +e
    git merge --no-ff --no-commit "$target_ref" >"$merge_log" 2>&1
    merge_code=$?
    set -e
    if (( merge_code != 0 )); then
      git diff --name-only --diff-filter=U | sort -u >"$conflict_file"
      git merge --abort
      write_report "conflict" "The upstream release conflicts with the deployed fork. The production branch was not changed." "$base_sha" "" "$conflict_file" "$failed_file"
      commit_report "chore: record upstream ${target_tag} conflict"
      bundle_branch
      printf 'result=conflict\n' >>"$GITHUB_OUTPUT"
      exit 0
    fi
    git commit -m "chore: merge upstream ${target_tag} for compatibility"
  fi
  candidate_sha="$(git rev-parse HEAD)"
  if run_validation "$failed_file"; then
    write_report "passed" "The upstream release merged cleanly and passed the complete Go test and build checks." "$base_sha" "$candidate_sha" "$conflict_file" "$failed_file"
    result="passed"
  else
    write_report "failed" "The upstream release merged, but one or more validation steps failed. The production branch was not changed." "$base_sha" "$candidate_sha" "$conflict_file" "$failed_file"
    result="failed"
  fi
  commit_report "chore: record upstream ${target_tag} compatibility result"
  bundle_branch
  printf 'result=%s\n' "$result" >>"$GITHUB_OUTPUT"
  exit 0
fi

git switch -C "$sync_branch" HEAD
base_sha="$(python3 -c 'import json; print(json.load(open(".codex/upstream-sync-status.json", encoding="utf-8"))["base_sha"])')"
reported_state="$(python3 -c 'import json; print(json.load(open(".codex/upstream-sync-status.json", encoding="utf-8"))["state"])')"
reported_tag="$(python3 -c 'import json; print(json.load(open(".codex/upstream-sync-status.json", encoding="utf-8"))["target_tag"])')"
if [[ "$reported_state" != "passed" || "$reported_tag" != "$target_tag" ]]; then
  printf 'The fixed branch has no passed report for %s\n' "$target_tag" >&2
  exit 3
fi
if [[ "$(git rev-parse origin/main)" != "$base_sha" ]]; then
  printf 'The production branch changed after the compatibility run\n' >&2
  exit 4
fi
if ! git merge-base --is-ancestor "$target_ref" HEAD; then
  printf 'The tested upstream tag is not contained in the fixed branch\n' >&2
  exit 5
fi
failed_file="$artifact_dir/failed-steps.txt"
conflict_file="$artifact_dir/conflict-files.txt"
: >"$conflict_file"
if ! run_validation "$failed_file"; then
  write_report "failed" "Promotion was cancelled because the repeated validation failed. The production branch was not changed." "$base_sha" "$(git rev-parse HEAD)" "$conflict_file" "$failed_file"
  commit_report "chore: record failed promotion validation for ${target_tag}"
  bundle_branch
  printf 'result=failed\n' >>"$GITHUB_OUTPUT"
  exit 0
fi
candidate_sha="$(git rev-parse HEAD)"
write_report "promoted" "The fixed branch passed validation again and is ready to replace the fork main branch." "$base_sha" "$candidate_sha" "$conflict_file" "$failed_file"
commit_report "chore: record upstream ${target_tag} promotion"
bundle_branch
printf 'result=passed\n' >>"$GITHUB_OUTPUT"
