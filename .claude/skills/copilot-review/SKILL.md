---
name: copilot-review
description: Address a round of GitHub Copilot review comments on a PR — batch fixes into one commit, push, re-request the Copilot review via the REST API (comments do NOT trigger re-review), reply per-thread with the fixing SHA, and leave thread resolution to the reviewer unless explicitly told to resolve.
---

# Copilot Review Round Workflow

Use this workflow whenever addressing GitHub Copilot review comments on a PR in this repo.

## Steps

1. **Batch the fixes**: address every comment from the round in a single commit named
   `Address Copilot's round-N review on <topic>`, with a multi-bullet body explaining each fix.

2. **Push** to the PR branch.

3. **Re-request the Copilot review — do NOT post an `@copilot` issue comment.**
   Comments never trigger a re-review; only an actual review request does. Also note that
   `gh pr edit --add-reviewer Copilot` does **not** work — it goes through GraphQL, which fails
   with `Could not resolve user with login 'copilot'`. Use the REST endpoint directly:

   ```bash
   gh api -X POST /repos/{owner}/{repo}/pulls/<PR#>/requested_reviewers \
     -f 'reviewers[]=copilot-pull-request-reviewer[bot]'
   ```

   On success, the PR's `requested_reviewers` array will contain
   `{"login": "Copilot", "type": "Bot"}`.

4. **Reply per-thread** with a commit-and-ping message referencing the SHA that fixed each comment:

   ```bash
   gh api -X POST /repos/{owner}/{repo}/pulls/{pr}/comments/{comment_id}/replies --input -
   ```

5. **Stop — leave thread resolution to Copilot or the PR author.** Open threads preserve the
   audit trail of the reviewer confirming each fix.

## Exception: explicit "resolve all comments"

Only when the user explicitly says to *resolve* the comments (e.g. stale threads piled up across
rounds), resolve them yourself via GraphQL:

```bash
gh api graphql -f query='mutation Resolve($threadId: ID!) {
  resolveReviewThread(input: {threadId: $threadId}) { thread { id isResolved } }
}' -F threadId=<PRRT_...>
```

Get thread IDs from GraphQL `repository.pullRequest.reviewThreads.nodes.id` — these are
`PRRT_...` node IDs, not REST comment IDs.
