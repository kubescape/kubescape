# Issue triage and contribution policy

This policy is implemented for `kubescape/kubescape`. Automation remains disabled
until maintainers set the `CONTRIBUTION_POLICY_START` repository variable to an
ISO UTC timestamp. PRs opened before that timestamp are exempt. The rules below
apply after activation, including to draft PRs.

## Picking up work

1. New issues receive `status: needs-triage`. A maintainer reviews the issue and
   removes the label when it is ready for work.
2. Read the issue and its prerequisites, then ask a maintainer to assign you.
   **Self-assignment is not allowed**, including `/assign-me` and a maintainer
   assigning themselves. Wait for another maintainer to assign you before
   starting. `/unassign-me` remains available to release your own assignment.
3. A contributor can hold at most **three open issue assignments**, including
   manually assigned issues. There is no open-PR limit. At most two of those
   assignments can carry any one of `good first issue` or `good second issue`.
4. Maintainers with write, maintain or admin permission can use `/assign @user`
   and `/unassign @user`. Assignment requires completed triage and available
   capacity. Issues already assigned to someone else require coordination.
5. The issue-assigned event also checks assignments made through GitHub's UI or
   API. Self-assignment is reversed with an explanation. A queued event does not
   undo a later valid assignment by another maintainer. GitHub administrators
   retain control of repository settings; this workflow enforces the process
   while enabled, rather than removing their platform permissions.

An inactive assignment receives a reminder after four days and becomes eligible
for release after eight days. The bot waits at least one day after a reminder
before releasing it. A progress comment by the assignee resets the timer; bot
comments do not. An open linked PR, including a draft, protects that author's
assignment. Maintainers can apply `📌 Pinned` for longer work. Assignments begun
before rollout, assignments with unknown start times, and maintainer assignments
are not expired automatically.

## Opening and updating a PR

Link each issue with `Fixes #number`, `Closes #number`, `Resolves #number` or
`Refs #number` for partial work. Same-repository issue URLs also work. Examples
inside HTML comments, code blocks or quotations do not count. Links to other
repositories or PR numbers do not satisfy this check.

The **Contribution policy** status checks that every referenced issue is open,
triaged and assigned to the author. A missing link or assignment fails the check
and produces one comment that is updated when the situation changes. Opening a
PR does not automatically assign its author to an issue.

A fixing PR for an issue still labelled `status: needs-triage` is automatically
closed with an explanation. `Refs` PRs stay open with a failed check. A pinned PR
is protected from automatic closure but must still pass the check to merge.
After triage and assignment, reopen the same PR.

Closing an unmerged PR releases its author's linked fixing-issue assignments,
unless another open fixing PR by that author still uses the issue or the issue
was reassigned after closure. Other contributors' assignments are preserved.

PRs by bots and maintainers are exempt from the contribution checks and automatic
closure. Exemption uses GitHub account type and current repository permission,
not an editable title prefix or branch name.

## Requested changes and inactivity

A PR with an outstanding change request from a human maintainer is marked
`status: stale` after three inactive days. A warning gives the author seven more
days to push changes or reply before automatic closure. PRs simply waiting for a
review are not closed. New commits, author replies, approval or dismissal of the
request, and `📌 Pinned` protect against closure. These checks run daily, so
labels may take until the next scheduled run to update. Inline replies count.
Reopening a PR starts a new inactivity warning window.

Only reviewers with repository write, maintain or admin permission can trigger
this lifecycle. Bot reviews and outside contributors' reviews do not.

## Maintainer activation

1. Agree to the repository-specific rules above. The central contribution guide
   currently permits small changes without an issue; align that guide or clearly
   retain its link to this repository-specific exception before rollout.
2. Create these labels if missing: `status: needs-triage`, `📍 Assigned`,
   `📌 Pinned`, and `status: stale`. The two beginner labels are optional.
3. Merge the workflow, script, tests and documentation together. The workflow
   requires only `GITHUB_TOKEN`, with contents read and issues, pull requests and
   commit statuses write permissions. No personal access token is needed.
4. Allow **only this workflow** to use `pull_request_target` in the repository or
   organization Actions event policy if the default policy blocks it. GitHub's
   announced public-repository default enforcement starts December 2, 2026.
   The checkout is pinned to `github.workflow_sha`; never change it to a PR head.
5. Set `CONTRIBUTION_POLICY_START` under **Settings → Secrets and variables →
   Actions → Variables**, to the agreed rollout instant, for example
   `2026-12-01T00:00:00Z`. Use the actual chosen date, not this example. Run the
   workflow manually and exercise a test issue and PR. Check the run logs and
   bot output before requiring the status.
6. In the ruleset targeting `master`, require the **Contribution policy** commit
   status and select GitHub Actions as its expected source. Required-check
   configuration needs a maintainer with the appropriate repository permissions.
   This workflow does not support merge queues: add and test `merge_group`
   evaluation before enabling it as a required check on a merge-queue branch.
7. The issue templates apply the triage label as soon as they are merged. If
   enforcement is delayed, maintainers should still triage those labelled issues.

To disable automation, remove `CONTRIBUTION_POLICY_START` and remove the required
status from the ruleset together, so PRs are not left waiting for a disabled check.
Keep the original rollout timestamp when re-enabling to preserve exemptions.

Values live in `.github/contribution-policy.json`. Commands are serialized across
the repository using a concurrency queue, and current state is fetched before
assignment. GitHub queues at most 100 pending runs; a command dropped because the
queue is full needs to be posted again. Scheduled runs reconcile PR checks, but
do not replay dropped assignment commands. API errors stop processing; a check
already being evaluated stays pending instead of retaining an earlier success.

The automation deliberately does not infer AI authorship, maintain contributor
blacklists or incident counters, or automatically approve/merge PRs. Those are
separate moderation and review decisions.

## Validation

Run `node --test .github/scripts/tests/contribution-policy.test.cjs` and
`go test ./internal/ghworkflows/...`. The node tests use an in-memory GitHub API;
real token permissions, event delivery and rulesets must be verified during
activation. Normal unprivileged PR CI runs these tests. The privileged automation
runs trusted workflow code only and does not run a PR's tests or build scripts.

GitHub references:

- [Actions event policies and pull_request_target](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [Concurrency queues](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
- [Required status checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)

Tooling note: actionlint v1.7.12 does not recognize GitHub's documented
`concurrency.queue` property. When using that version, exclude only its
`unexpected key "queue" for "concurrency" section` diagnostic. Keep the queue;
removing it causes pending assignment commands to replace each other.
