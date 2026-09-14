# Codex Upstream Sync Handoff

## User intent

Keep this fork compatible with upstream CLIProxyAPI releases without silently losing the fork-specific behavior used by the deployed LiteLLM account pool. Every upstream update must be merged and tested on one fixed branch before it can reach `main`.

## Fixed repositories and branch

- Upstream: `router-for-me/CLIProxyAPI`
- Fork: `VVV-345/CLIProxyAPI`
- Production branch: `main`
- Compatibility branch: `codex/upstream-sync`
- Workflow: `.github/workflows/upstream-sync.yml`

Always reuse `codex/upstream-sync`. Do not create a new branch for each upstream version.

## Current deployed baseline

- Upstream baseline: `v7.2.146`
- Fork source commit: `e851070a0d08fb631d5ee7c64ecfab9a30ecbd2a`
- Image tag: `sha-e851070a0d08fb631d5ee7c64ecfab9a30ecbd2a`
- Image digest: `sha256:d1099dc145e86db0cf87a43e0812af541f725f274dd0502d23ce3e49fbc771b6`

The production server remains on that pinned image until a separately approved deployment changes the image digest.

## Fork behavior that must survive upstream merges

1. Codex request identity convergence introduced by commit `293ff4ac`
2. Pre-request refresh for expiring xAI credentials introduced by commit `e851070a`
3. Existing Git store recovery fixes already included in the deployed baseline
4. GHCR commit image publishing used by the LiteLLM account pool

Review semantic behavior, not only whether Git reports a clean merge. Upstream changes in Codex request construction, WebSocket execution, auth metadata, token refresh, configuration schema, or model discovery require explicit comparison with these fork changes.

## Automated workflow

The management UI dispatches the upstream sync workflow with a release tag and request ID.

For an analysis run, the workflow:

1. Resets the fixed compatibility branch to the current fork `main`
2. Fetches the exact upstream release tag
3. Attempts the merge on the compatibility branch
4. Runs `go test ./...`
5. Runs `go build -o <temporary-path> ./cmd/server`
6. Writes `.codex/upstream-sync-status.json` and `.codex/upstream-sync-review.md`
7. Publishes the result back to the fixed compatibility branch

Conflicts or test failures must never modify `main`. A promotion run is allowed only when the status is `passed`, the tested tag matches the requested tag, the current `main` is still the candidate base, and all tests pass again. After the successful push to `main`, the promotion job explicitly dispatches the existing `docker-image.yml` workflow once.

## Codex repair procedure

When asked to review or repair a failed synchronization:

1. Read this file, `AGENTS.md`, `.codex/upstream-sync-status.json`, and `.codex/upstream-sync-review.md`
2. Fetch both `origin/main` and the requested upstream tag
3. Work only on `codex/upstream-sync`
4. Reproduce the merge if the report state is `conflict`
5. Preserve the fork behavior listed above while resolving conflicts or test failures
6. Run the complete Go test and build commands from `AGENTS.md`
7. Commit repairs to the fixed compatibility branch
8. Run the compatibility analysis again so the repaired branch receives a `passed` report
9. Do not merge to `main`, publish a production image, or deploy unless the user explicitly requests promotion

Never include OAuth files, access tokens, refresh tokens, GitHub credentials, or production configuration in the review report.
