'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { run, issueLinks, assignmentProblem, assignmentActivity, changesRequested } = require('../contribution-policy.cjs');
const config = require('../../contribution-policy.json');
const DAY = 86_400_000;
const epoch = Date.parse('2026-12-01T00:00:00Z');
const date = day => new Date(epoch + day * DAY).toISOString();
const user = (login, type = 'User') => ({ login, type });
const label = name => ({ name });
const issue = (number, overrides = {}) => ({ number, state: 'open', labels: [], assignees: [], user: user('reporter'), created_at: date(1), updated_at: date(1), ...overrides });
const pr = (number = 10, overrides = {}) => ({ ...issue(number), user: user('alice'), body: 'Fixes #1', head: { sha: 'a'.repeat(40) }, merged: false, ...overrides });

function fixture({ issues = [issue(1, { assignees: [user('alice')] })], prs = [], day = 12 } = {}) {
  const state = { issues: new Map(issues.map(i => [i.number, structuredClone(i)])), prs: new Map(prs.map(p => [p.number, structuredClone(p)])), comments: new Map(), events: new Map(), reviews: new Map(), inline: new Map(), permissions: new Map([['maintainer', 'write']]), statuses: [], mutations: [] };
  let id = 100;
  const now = epoch + day * DAY;
  const endpoint = handler => async args => ({ data: structuredClone(await handler(args)) });
  const getItem = n => state.prs.get(n) ?? state.issues.get(n);
  const rest = {
    issues: {
      get: endpoint(a => { const item = getItem(a.issue_number); if (!item) throw Object.assign(new Error('missing'), { status: 404 }); return state.prs.has(a.issue_number) ? { ...item, pull_request: {} } : item; }),
      listForRepo: endpoint(a => [...state.issues.values()].filter(i => (!a.state || i.state === a.state) && (!a.assignee || i.assignees.some(u => u.login === a.assignee)) && (!a.labels || i.labels.some(l => l.name === a.labels)))),
      listComments: endpoint(a => state.comments.get(a.issue_number) ?? []),
      getComment: endpoint(a => [...state.comments.values()].flat().find(c => c.id === a.comment_id)),
      listEventsForTimeline: endpoint(a => state.events.get(a.issue_number) ?? []),
      createComment: endpoint(a => { const c = { id: id++, user: user('github-actions[bot]', 'Bot'), body: a.body, created_at: date(day), updated_at: date(day) }; state.comments.set(a.issue_number, [...(state.comments.get(a.issue_number) ?? []), c]); state.mutations.push(['comment', a.issue_number]); return c; }),
      updateComment: endpoint(a => { const c = [...state.comments.values()].flat().find(c => c.id === a.comment_id); c.body = a.body; c.updated_at = date(day); return c; }),
      addLabels: endpoint(a => { const item = getItem(a.issue_number); item.labels.push(...a.labels.map(label)); item.updated_at = date(day); return item.labels; }),
      removeLabel: endpoint(a => { const item = getItem(a.issue_number); item.labels = item.labels.filter(l => l.name !== a.name); item.updated_at = date(day); return item.labels; }),
      addAssignees: endpoint(a => { const item = getItem(a.issue_number); item.assignees.push(...a.assignees.map(u => user(u))); state.mutations.push(['assign', a.issue_number]); return item; }),
      removeAssignees: endpoint(a => { const item = getItem(a.issue_number); item.assignees = item.assignees.filter(u => !a.assignees.includes(u.login)); state.mutations.push(['unassign', a.issue_number]); return item; }),
    },
    pulls: {
      get: endpoint(a => state.prs.get(a.pull_number)),
      list: endpoint(a => [...state.prs.values()].filter(p => p.state === a.state)),
      listReviews: endpoint(a => state.reviews.get(a.pull_number) ?? []),
      listReviewComments: endpoint(a => state.inline.get(a.pull_number) ?? []),
      update: endpoint(a => { const p = state.prs.get(a.pull_number); p.state = a.state; p.closed_at = date(day); state.mutations.push(['close', a.pull_number]); return p; }),
    },
    repos: {
      getCollaboratorPermissionLevel: endpoint(a => ({ permission: state.permissions.get(a.username) ?? 'read' })),
      createCommitStatus: endpoint(a => { state.statuses.push(a); return a; }),
    },
  };
  const github = { rest, paginate: async (method, args) => { assert.equal(args.per_page, 100); return (await method(args)).data; } };
  const execute = (eventName, payload = {}, overrides = {}) => run({ github, context: { repo: { owner: 'kubescape', repo: 'kubescape' }, eventName, payload }, core: { info() {} }, start: date(0), now, ...overrides });
  const command = async (number, body, login = 'alice') => {
    const comment = { id: id++, user: user(login), body, created_at: date(day), updated_at: date(day) };
    state.comments.set(number, [...(state.comments.get(number) ?? []), comment]);
    const payload = { issue: structuredClone(state.issues.get(number)), comment };
    await execute('issue_comment', payload);
    return payload;
  };
  return { state, execute, command, now, github };
}

test('links accept closing variants and local URLs, excluding foreign repositories and examples', () => {
  const body = 'Resolved #1\nRefs #1\nCloses https://github.com/kubescape/kubescape/issues/2\nFixes kubescape/kubescape#3\nFixes other/repo#4\n<!-- Fixes #5 -->\n```sh\nFixes #6\n```\n> Fixes #7\n`Fixes #8`';
  assert.deepEqual(issueLinks(body, 'kubescape/kubescape'), [{ number: 1, closes: true }, { number: 2, closes: true }, { number: 3, closes: true }]);
  assert.deepEqual(issueLinks('Fixes #9abc; Refs #10', 'kubescape/kubescape'), [{ number: 10, closes: false }]);
});

test('third assignment is allowed, fourth is refused; closed issues and PRs do not consume slots', () => {
  const assigned = [1, 2, 3].map(n => issue(n, { assignees: [user('alice')] }));
  assert.equal(assignmentProblem(issue(9), 'alice', assigned.slice(0, 2)), '');
  assert.match(assignmentProblem(issue(9), 'alice', assigned), /3 active/);
  assigned[2].state = 'closed';
  assigned.push({ ...issue(4, { assignees: [user('alice')] }), pull_request: {} });
  assert.equal(assignmentProblem(issue(9), 'alice', assigned), '');
});

test('maintainer assignment still rejects untriaged or occupied issues', () => {
  for (const target of [issue(1, { labels: [label(config.needsTriageLabel)] }), issue(1, { assignees: [user('bob')] })]) {
    assert.notEqual(assignmentProblem(target, 'alice', []), '');
  }
  assert.equal(assignmentProblem(issue(1, { user: user('alice') }), 'alice', []), '');
});

test('beginner limits count open assignments with the same label', () => {
  const target = issue(9, { labels: [label('good first issue')] });
  const current = [1, 2].map(n => issue(n, { labels: [label('good first issue')], assignees: [user('alice')] }));
  assert.match(assignmentProblem(target, 'alice', current), /good first issue/);
  current[1].state = 'closed';
  assert.equal(assignmentProblem(target, 'alice', current), '');
});

test('dismissal and approval supersede requested changes; plain comments do not', () => {
  const reviews = [{ id: 1, user: user('r'), state: 'CHANGES_REQUESTED' }, { id: 2, user: user('r'), state: 'COMMENTED' }];
  assert.equal(changesRequested(reviews).length, 1);
  assert.equal(changesRequested([...reviews, { id: 3, user: user('r'), state: 'DISMISSED' }]).length, 0);
});

test('reminder bot activity cannot extend an assignment', () => {
  const events = [{ event: 'assigned', assignee: user('alice'), created_at: date(1) }];
  assert.equal(assignmentActivity(events, [{ user: user('github-actions[bot]', 'Bot'), created_at: date(10) }], 'alice'), epoch + DAY);
  assert.equal(assignmentActivity(events, [{ user: user('alice'), updated_at: date(5) }], 'alice'), epoch + 5 * DAY);
});

test('queued commands use current issue labels instead of the event snapshot', async () => {
  const f = fixture({ issues: [issue(1)] });
  const comment = { id: 1, body: '/assign @alice', user: user('maintainer') };
  f.state.comments.set(1, [comment]);
  f.state.issues.get(1).labels.push(label(config.needsTriageLabel));
  await f.execute('issue_comment', { issue: issue(1), comment });
  assert.equal(f.state.issues.get(1).assignees.length, 0);
});

test('command retries do not duplicate assignment or confirmation; fake bot markers do not suppress commands', async () => {
  const f = fixture({ issues: [issue(1)] });
  const payload = await f.command(1, '/assign @alice', 'maintainer');
  await f.execute('issue_comment', payload);
  assert.equal(f.state.mutations.filter(m => m[0] === 'assign').length, 1);
  assert.equal(f.state.comments.get(1).filter(c => c.user.type === 'Bot').length, 1);
  const g = fixture({ issues: [issue(1)] });
  g.state.comments.set(1, [{ id: 2, user: user('bob'), body: '<!-- kubescape-policy:command-100 -->' }]);
  await g.command(1, '/assign @alice', 'maintainer');
  assert.equal(g.state.issues.get(1).assignees[0].login, 'alice');
});

test('only maintainers can use manual assignment commands', async () => {
  const f = fixture({ issues: [issue(1)] });
  await f.command(1, '/assign @bob');
  assert.equal(f.state.issues.get(1).assignees.length, 0);
  await f.command(1, '/assign @bob', 'maintainer');
  assert.equal(f.state.issues.get(1).assignees[0].login, 'bob');
});

test('new issues get needs-triage even when created without a template', async () => {
  const f = fixture({ issues: [issue(1)] });
  await f.execute('issues', { action: 'opened', issue: issue(1) });
  assert.deepEqual(f.state.issues.get(1).labels, [label(config.needsTriageLabel)]);
});

test('PR with assigned triaged issue passes on the live head', async () => {
  const f = fixture({ prs: [pr()] });
  await f.execute('pull_request_target', { pull_request: pr(10, { head: { sha: 'old' } }) });
  assert.equal(f.state.statuses.at(-1).state, 'success');
  assert.equal(f.state.statuses.at(-1).sha, 'a'.repeat(40));
});

test('fixing PR for an untriaged issue closes and releases only its own assignment', async () => {
  const f = fixture({ issues: [issue(1, { labels: [label(config.needsTriageLabel)], assignees: [user('alice'), user('bob')] })], prs: [pr()] });
  await f.execute('pull_request_target', { pull_request: pr() });
  assert.equal(f.state.prs.get(10).state, 'closed');
  assert.equal(f.state.statuses.at(-1).state, 'failure');
  assert.deepEqual(f.state.issues.get(1).assignees, [user('bob')]);
});

test('Refs on an untriaged issue fails the check without closing', async () => {
  const f = fixture({ issues: [issue(1, { labels: [label(config.needsTriageLabel)], assignees: [user('alice')] })], prs: [pr(10, { body: 'Refs #1' })] });
  await f.execute('pull_request_target', { pull_request: pr() });
  assert.equal(f.state.prs.get(10).state, 'open');
  assert.equal(f.state.statuses.at(-1).state, 'failure');
});

test('missing links, foreign links, nonexistent issues and PR-as-issue fail without closing', async () => {
  for (const body of ['', 'Fixes other/repo#1', 'Fixes #999', 'Fixes #10']) {
    const f = fixture({ prs: [pr(10, { body })] });
    await f.execute('pull_request_target', { pull_request: pr() });
    assert.equal(f.state.statuses.at(-1).state, 'failure', body);
    assert.equal(f.state.prs.get(10).state, 'open');
  }
});

test('an issue change refreshes the failed PR check, including bot-triggered assignment in the same run', async () => {
  const f = fixture({ issues: [issue(1)], prs: [pr()] });
  await f.execute('pull_request_target', { pull_request: pr() });
  assert.equal(f.state.statuses.at(-1).state, 'failure');
  await f.command(1, '/assign @alice', 'maintainer');
  assert.equal(f.state.statuses.at(-1).state, 'success');
});

test('bot, maintainer and pre-rollout PRs remain exempt', async () => {
  for (const override of [{ user: user('dependabot[bot]', 'Bot') }, { user: user('maintainer') }, { created_at: date(-1) }]) {
    const f = fixture({ prs: [pr(10, { body: '', ...override })] });
    await f.execute('pull_request_target', { pull_request: pr() });
    assert.equal(f.state.statuses.at(-1).state, 'success');
  }
});

test('closing one of two linked PRs does not release the active assignment', async () => {
  const f = fixture({ prs: [pr(10, { state: 'closed', closed_at: date(11) }), pr(11)] });
  await f.execute('pull_request_target', { pull_request: pr() });
  assert.deepEqual(f.state.issues.get(1).assignees, [user('alice')]);
});

test('old closure events cannot release a later reassignment', async () => {
  const f = fixture({ prs: [pr(10, { state: 'closed', closed_at: date(10) })] });
  f.state.events.set(1, [{ event: 'assigned', assignee: user('alice'), created_at: date(11) }]);
  await f.execute('pull_request_target', { pull_request: pr() });
  assert.equal(f.state.issues.get(1).assignees.length, 1);
});

test('inactivity gives a reminder before expiry, then releases without counting bot activity', async () => {
  const f = fixture({ issues: [issue(1, { labels: [label(config.assignedLabel)], assignees: [user('alice')] })] });
  f.state.events.set(1, [{ event: 'assigned', assignee: user('alice'), created_at: date(1) }]);
  await f.execute('schedule');
  assert.equal(f.state.issues.get(1).assignees.length, 1);
  assert.match(f.state.comments.get(1)[0].body, /reminder/);
  await f.execute('schedule', {}, { now: f.now + DAY });
  assert.equal(f.state.issues.get(1).assignees.length, 0);
});

test('a linked draft PR or pinned issue protects its assignment from expiry', async () => {
  for (const pinned of [false, true]) {
    const f = fixture({ issues: [issue(1, { labels: [label(config.assignedLabel), ...(pinned ? [label(config.pinnedLabel)] : [])], assignees: [user('alice')] })], prs: pinned ? [] : [pr(10, { draft: true })] });
    f.state.events.set(1, [{ event: 'assigned', assignee: user('alice'), created_at: date(1) }]);
    await f.execute('schedule');
    assert.equal(f.state.issues.get(1).assignees.length, 1);
    assert.equal(f.state.comments.get(1)?.length ?? 0, 0);
  }
});

function staleFixture() {
  const f = fixture({ prs: [pr(10, { labels: [label(config.staleLabel)] })] });
  f.state.reviews.set(10, [{ id: 1, user: user('maintainer'), state: 'CHANGES_REQUESTED', submitted_at: date(2) }]);
  f.state.comments.set(10, [{ id: 50, user: user('github-actions[bot]', 'Bot'), created_at: date(4), body: `<!-- kubescape-policy:stale-${'a'.repeat(40)}-123 -->\nReminder` }]);
  return f;
}

test('stale requested changes close after seven warning days and release the issue', async () => {
  const f = staleFixture();
  await f.execute('schedule');
  assert.equal(f.state.prs.get(10).state, 'closed');
  assert.equal(f.state.issues.get(1).assignees.length, 0);
});

test('author reply, new head, dismissed request, or pin prevents stale closure', async () => {
  for (const change of ['reply', 'push', 'dismiss', 'pin']) {
    const f = staleFixture();
    if (change === 'reply') f.state.inline.set(10, [{ user: user('alice'), created_at: date(10) }]);
    if (change === 'push') f.state.prs.get(10).head.sha = 'b'.repeat(40);
    if (change === 'dismiss') f.state.reviews.get(10).push({ id: 2, user: user('maintainer'), state: 'DISMISSED', submitted_at: date(10) });
    if (change === 'pin') f.state.prs.get(10).labels.push(label(config.pinnedLabel));
    await f.execute('schedule');
    assert.equal(f.state.prs.get(10).state, 'open', change);
  }
});

test('outsider or bot requests cannot cause automatic closure', async () => {
  for (const reviewer of [user('outsider'), user('review-bot', 'Bot')]) {
    const f = staleFixture();
    f.state.reviews.get(10)[0].user = reviewer;
    await f.execute('schedule');
    assert.equal(f.state.prs.get(10).state, 'open');
  }
});

test('API failure cannot turn an unknown issue into an automatic closure', async () => {
  const f = fixture({ prs: [pr()] });
  f.github.rest.issues.get = async () => { throw Object.assign(new Error('unavailable'), { status: 503 }); };
  await assert.rejects(f.execute('pull_request_target', { pull_request: pr() }), /unavailable/);
  assert.equal(f.state.prs.get(10).state, 'open');
});

test('invalid rollout timestamp stops before writes', async () => {
  const f = fixture({ prs: [pr()] });
  await assert.rejects(f.execute('schedule', {}, { start: 'yesterday' }), /ISO UTC/);
  assert.deepEqual(f.state.mutations, []);
});


test('API failure replaces a previous passing status with pending', async () => {
  const f = fixture({ prs: [pr()] });
  await f.execute('pull_request_target', { pull_request: pr() });
  assert.equal(f.state.statuses.at(-1).state, 'success');
  f.github.rest.issues.get = async () => { throw new Error('outage'); };
  await assert.rejects(f.execute('pull_request_target', { pull_request: pr() }), /outage/);
  assert.equal(f.state.statuses.at(-1).state, 'pending');
});

test('queued opened event does not undo completed triage', async () => {
  const f = fixture({ issues: [issue(1)] });
  f.state.events.set(1, [{ event: 'unlabeled', label: label(config.needsTriageLabel), created_at: date(2) }]);
  await f.execute('issues', { action: 'opened', issue: issue(1) });
  assert.deepEqual(f.state.issues.get(1).labels, []);
});

test('triage completed during a check prevents automatic closure', async () => {
  const f = fixture({ issues: [issue(1, { labels: [label(config.needsTriageLabel)], assignees: [user('alice')] })], prs: [pr()] });
  const writeStatus = f.github.rest.repos.createCommitStatus;
  f.github.rest.repos.createCommitStatus = async a => {
    const result = await writeStatus(a);
    if (a.state === 'failure') f.state.issues.get(1).labels = [];
    return result;
  };
  await f.execute('pull_request_target', { pull_request: pr() });
  assert.equal(f.state.prs.get(10).state, 'open');
});


test('a new round of requested changes cannot reuse an older stale warning', async () => {
  const f = staleFixture();
  f.state.reviews.get(10).push({ id: 2, user: user('maintainer'), state: 'CHANGES_REQUESTED', submitted_at: date(11) });
  await f.execute('schedule');
  assert.equal(f.state.prs.get(10).state, 'open');
  assert.ok(!f.state.prs.get(10).labels.some(l => l.name === config.staleLabel));
});

test('an author review reply counts as activity', async () => {
  const f = staleFixture();
  f.state.reviews.get(10).push({ id: 2, user: user('alice'), state: 'COMMENTED', submitted_at: date(11) });
  await f.execute('schedule');
  assert.equal(f.state.prs.get(10).state, 'open');
});

test('pre-rollout assignments remain exempt even after a new progress comment', async () => {
  const f = fixture({ issues: [issue(1, { labels: [label(config.assignedLabel)], assignees: [user('alice')] })] });
  f.state.events.set(1, [{ event: 'assigned', assignee: user('alice'), created_at: date(-1) }]);
  f.state.comments.set(1, [{ user: user('alice'), created_at: date(1) }]);
  await f.execute('schedule');
  assert.equal(f.state.comments.get(1).length, 1);
  assert.equal(f.state.issues.get(1).assignees.length, 1);
});


test('angle-bracketed same-repository issue URLs are accepted', () => {
  assert.deepEqual(issueLinks('Fixes <https://github.com/kubescape/kubescape/issues/12>', 'kubescape/kubescape'), [{ number: 12, closes: true }]);
});

test('requested changes get a warning first; waiting for review does not', async () => {
  const f = fixture({ prs: [pr()], day: 5 });
  f.state.reviews.set(10, [{ id: 1, user: user('maintainer'), state: 'CHANGES_REQUESTED', submitted_at: date(1) }]);
  await f.execute('schedule');
  assert.equal(f.state.prs.get(10).state, 'open');
  assert.ok(f.state.prs.get(10).labels.some(l => l.name === config.staleLabel));
  assert.match(f.state.comments.get(10).at(-1).body, /within 7 days/);
  const g = fixture({ prs: [pr()], day: 100 });
  await g.execute('schedule');
  assert.equal(g.state.prs.get(10).state, 'open');
  assert.equal(g.state.comments.get(10)?.length ?? 0, 0);
});


test('reply or approval arriving during stale processing prevents closure', async () => {
  for (const change of ['reply', 'approval']) {
    const f = staleFixture();
    const get = f.github.rest.pulls.get;
    let reads = 0;
    f.github.rest.pulls.get = async args => {
      reads++;
      if (reads === 3) { // The final close guard, after expiry read the old state.
        if (change === 'reply') f.state.comments.get(10).push({ id: 51, user: user('alice'), created_at: date(12), body: 'Working on this.' });
        else f.state.reviews.get(10).push({ id: 2, user: user('maintainer'), state: 'APPROVED', submitted_at: date(12) });
      }
      return get(args);
    };
    await f.execute('schedule');
    assert.equal(f.state.prs.get(10).state, 'open', change);
  }
});

test('progress or a pin arriving during assignment expiry prevents unassignment', async () => {
  for (const change of ['progress', 'pin']) {
    const f = fixture({ issues: [issue(1, { labels: [label(config.assignedLabel)], assignees: [user('alice')] })] });
    f.state.events.set(1, [{ event: 'assigned', assignee: user('alice'), created_at: date(1) }]);
    f.state.comments.set(1, [{ id: 1, user: user('github-actions[bot]', 'Bot'), created_at: date(5), body: `<!-- kubescape-policy:assignment-reminder-alice-${epoch + DAY} -->` }]);
    const getComments = f.github.rest.issues.listComments;
    let injected = false;
    f.github.rest.issues.listComments = async args => {
      const result = await getComments(args);
      if (!injected) {
        injected = true;
        if (change === 'pin') f.state.issues.get(1).labels.push(label(config.pinnedLabel));
        else f.state.comments.get(1).push({ id: 2, user: user('alice'), created_at: date(12), body: 'Progress update' });
      }
      return result;
    };
    await f.execute('schedule');
    assert.equal(f.state.issues.get(1).assignees.length, 1, change);
  }
});

test('deleted queued commands are ignored', async () => {
  const f = fixture({ issues: [issue(1)] });
  f.github.rest.issues.getComment = async () => { throw Object.assign(new Error('deleted'), { status: 404 }); };
  await f.execute('issue_comment', { issue: issue(1), comment: { id: 1, user: user('alice') } });
  assert.equal(f.state.issues.get(1).assignees.length, 0);
});

test('reopening an inactive PR starts a new warning window', async () => {
  const f = staleFixture();
  f.state.prs.get(10).updated_at = date(12);
  await f.execute('pull_request_target', { action: 'reopened', pull_request: pr() });
  await f.execute('schedule');
  assert.equal(f.state.prs.get(10).state, 'open');
  assert.ok(!f.state.prs.get(10).labels.some(l => l.name === config.staleLabel));
});


test('all self-assignment commands are rejected, including maintainer aliases', async () => {
  for (const [login, command] of [['alice', '/assign-me'], ['maintainer', '/assign-me'], ['maintainer', '/assign @maintainer']]) {
    const f = fixture({ issues: [issue(1)] });
    await f.command(1, command, login);
    assert.equal(f.state.issues.get(1).assignees.length, 0);
    assert.match(f.state.comments.get(1).at(-1).body, /Self-assignment is not allowed/);
  }
});

test('maintainer assignment cannot exceed three active assignments', async () => {
  const f = fixture({ issues: [issue(1), ...[2, 3, 4].map(n => issue(n, { assignees: [user('alice')] }))] });
  await f.command(1, '/assign @alice', 'maintainer');
  assert.equal(f.state.issues.get(1).assignees.length, 0);
  assert.match(f.state.comments.get(1).at(-1).body, /3 active issue assignments/);
});

test('self-assignment through GitHub UI is reversed; later maintainer assignment is preserved', async () => {
  for (const laterAssignment of [false, true]) {
    const f = fixture();
    f.state.events.set(1, [{ id: 1, event: 'assigned', assignee: user('alice'), actor: user('alice'), created_at: date(11) }]);
    if (laterAssignment) f.state.events.get(1).push({ id: 2, event: 'assigned', assignee: user('alice'), actor: user('maintainer'), created_at: date(12) });
    await f.execute('issues', { action: 'assigned', issue: issue(1), assignee: user('alice'), sender: user('alice') });
    assert.equal(f.state.issues.get(1).assignees.length, laterAssignment ? 1 : 0);
  }
});

test('contributors may still release their own assignment', async () => {
  const f = fixture();
  await f.command(1, '/unassign-me');
  assert.equal(f.state.issues.get(1).assignees.length, 0);
});
