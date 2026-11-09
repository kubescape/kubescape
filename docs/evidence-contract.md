# Evidence of Finding: A Guide for Rule Authors

Kubescape can show not only that a control failed but also why: the field that triggered the failure, the value it holds, and the line of the manifest to look at. This document describes what a rule has to emit for that to work, what Kubescape does with it, and the ways a rule can end up producing no evidence without any error.

It is written for authors of [regolibrary](https://github.com/kubescape/regolibrary) rules and of custom rules loaded with `--custom-rules`. The design behind the feature is in the [Evidence of Finding proposal](https://github.com/kubescape/designs-and-proposals/blob/main/proposals/evidence-of-finding.md), and the original request is [#1563](https://github.com/kubescape/kubescape/issues/1563).

---

## Table of Contents

- [Evidence at a Glance](#evidence-at-a-glance)
- [What a Rule Emits](#what-a-rule-emits)
- [Writing a Path That Resolves](#writing-a-path-that-resolves)
- [What the User Sees](#what-the-user-sees)
- [Ways Evidence Goes Missing](#ways-evidence-goes-missing)
- [Testing Your Rule](#testing-your-rule)
- [Checklist](#checklist)

---

## Evidence at a Glance

Take this manifest, saved as `pod.yaml`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: demo
spec:
  hostNetwork: true
  containers:
  - name: app
    image: nginx:1.25
    env:
    - name: LOG_LEVEL
      value: debug
    - name: DB_PASSWORD
      value: example
```

Scanning it with `--show-evidence` (`-E`) adds an evidence entry under each failed control. This is the "Assisted remediation" column of the output, condensed:

```
kubescape scan control C-0012,C-0017,C-0041 pod.yaml -E

C-0012  @ pod.yaml
        spec.containers[0].env[1].name (app) (line 13)
        spec.containers[0].env[1].value (app) (line 14)
C-0017  @ pod.yaml
        spec.containers[0].securityContext.readOnlyRootFilesystem=true (app) (line 8)
C-0041  @ pod.yaml
        spec.hostNetwork (line 6)
```

Each entry is a **path** into the resource, optionally followed by `=<value>`, the container it belongs to in parentheses, and the **line** in the manifest. The path, and the value after `=` on a fix path, come from the rule. The container name and the line are added by Kubescape.

---

## What a Rule Emits

A Rego rule reports a failure by adding an object to its `deny` set. The paths that become evidence are fields of that object. This is the first `deny` block of the `host-network-access` rule behind C-0041, shortened:

```rego
deny contains msga if {
	path := "spec.hostNetwork"
	pods := [pod | pod = input[_]; pod.kind == "Pod"]
	pod := pods[_]

	is_host_network(pod.spec)
	msga := {
		"alertMessage": sprintf("Pod: %v is connected to the host network", [pod.metadata.name]),
		"alertScore": 9,
		"deletePaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [pod]},
	}
}
```

| Field | Meaning in the report model | Used as evidence |
|-------|-----------------------------|------------------|
| `deletePaths` | Paths in the YAML to delete to remediate the resource | Yes |
| `reviewPaths` | Paths in the YAML that led to the failure of the resource | Yes. Printed with the field's current value |
| `fixPaths` | `{"path": ..., "value": ...}` objects: fields to add or set to fix the resource | Yes. Printed as `path=value`, where the value is what the rule wants, not what the manifest holds |
| `failedPaths` | Marked for deprecation in the report model | **No.** Kubescape does not read it |
| `alertObject.k8sApiObjects` | The resource the finding is about | Paths are resolved against it |

A path is resolved against the object it is attached to. For a finding that names related objects, each entry in `relatedObjects` carries its own paths, and they are resolved against that object.

### Choosing the kind of path

- The field is present and is what caused the failure, and the person should look at its value: `reviewPaths`.
- The field is present and removing it is the remedy: `deletePaths`, as `host-network-access` does.
- The field is missing and has to be added: `fixPaths` with the value the policy requires. The path will not exist in the manifest, and that is expected (see [absent fields](#absent-fields)).

Do not rely on `failedPaths`. Many rules still emit it next to the paths above, which is harmless, but a path that appears only there produces no evidence.

---

## Writing a Path That Resolves

### Syntax

A path is a dot-separated list of keys. A list element is selected with a numeric index attached to the key before it, and a map key that cannot be written as a plain key goes in brackets.

| Path | Reads as |
|------|----------|
| `spec.containers[0].image` | the `image` field of the first container |
| `metadata.labels[app.kubernetes.io/name]` | the label whose key is `app.kubernetes.io/name` |
| `metadata.annotations."foo.bar/baz"` | the annotation whose key is `foo.bar/baz` |
| `data['0']` | the entry named `0`. Quoting is how a path says "key, not index" |

An unquoted key holds only letters, digits, `_`, `-` and `/`, plus `.` when it is inside brackets. A quoted key can hold anything else.

Paths outside this syntax are rejected rather than approximated, because a guess would point at a line the rule never named. Rejected forms include a wildcard (`spec.containers[*].image`), an empty segment (`spec..image`), an unclosed bracket or quote, and a second index on one key (`a[0][1]`). A rejected path gets no line and no value from the resource.

Always substitute indexes into the path, the way the library's rules do:

```rego
path := sprintf("spec.containers[%v].env[%v].name", [i, j])
```

A bracket that is not a number is read as a map key. An index left as a placeholder, such as `spec.containers[container_ndx]`, names a key that does not exist, so it gets no line and no value.

### The root depends on the kind

A path starts at the root of the resource it is attached to, so the same field has a different path on each kind. The `host-network-access` rule has one `deny` block per shape:

| Kind | Path |
|------|------|
| Pod | `spec.hostNetwork` |
| Deployment, ReplicaSet, DaemonSet, StatefulSet, Job | `spec.template.spec.hostNetwork` |
| CronJob | `spec.jobTemplate.spec.template.spec.hostNetwork` |

### A wrong root does not fail loudly

If a well-formed path names a field that is missing from the resource, Kubescape does not report an error. It looks for the nearest enclosing block that does exist and uses that. This is deliberate, because a fix path routinely names a field that has to be added, but it means a path written for the wrong kind still gets a line number. It is a nearby line, not the field's. (A malformed path, or one that indexes a list with a name instead of a number, is the exception: it gets no line.)

Here is a custom rule with two `deny` blocks that both match a Pod with `hostNetwork: true`. Only the `reviewPaths` line differs between them:

```rego
"reviewPaths": ["spec.hostNetwork"],                 # first block: the right root for a Pod
"reviewPaths": ["spec.template.spec.hostNetwork"],   # second block: the root for a Deployment
```

Against this manifest:

```yaml
apiVersion: v1          # 1
kind: Pod               # 2
metadata:               # 3
  name: demo            # 4
spec:                   # 5
  containers:           # 6
  - name: app           # 7
    image: nginx:1.25   # 8
  hostNetwork: true     # 9
```

the output is:

```
spec.hostNetwork (current: true) (line 9)
spec.template.spec.hostNetwork (line 6)
```

The right path shows the current value and points at line 9. The wrong one shows no value and points at line 6, the first line inside the enclosing `spec`. A review path with no `(current: ...)` has usually not resolved.

### Absent fields

For a field that the rule says must be added, the line points at the enclosing block. In the first example, `securityContext` does not exist, so the C-0017 fix path is reported at line 8, the container entry that needs it. If no enclosing block exists at all, no line is shown.

---

## What the User Sees

### Values

Review paths are printed with the field's current value, as `path (current: value)`. Fix paths are printed as `path=value` with the value the rule wants.

The default JSON format carries the same paths in each rule's results, and also an `evidence` array of `path`/`value` pairs for the delete and review paths of each failed control:

```json
"evidence": [{"path": "spec.hostNetwork", "value": "true"}]
```

The array is left out of a control when none of its values resolve, and `--show-evidence` is not needed for it to appear. It does not exist in the older v1 format (`--format-version v1`). There, each rule response in `controlReports[].ruleReports[].ruleResponses[]` lists its paths as `reviewPaths`, `deletePaths` and `fixPaths` arrays, without values, and `failedPaths` comes back empty.

The SARIF, HTML, CSV, GitLab SAST and GitHub Actions outputs read the same path kinds.

**Fix values are not redacted in JSON.** The rule results of both JSON formats carry each fix-path value exactly as the rule wrote it: `results[].controls[].rules[].paths[].fixPath.value` in v2 and `fixPaths[].value` in v1. The `evidence` array is the filtered part. These fields are not, and `--show-secrets` plays no part in them. A fix value that contains a credential would therefore appear in a JSON report, so a rule must never put one there. JSON reports also include the scanned resources, so a credential in a field that the scrub below does not overwrite appears there too. In v2, `--omit-raw-resources` removes them. In v1 it does not remove everything: each failed resource is still copied into its rule response's `alertObject.k8sApiObjects`, without its `spec` but with its `metadata`, so an annotation that holds a credential still appears. Check a report before sharing it, and in v1 inspect the alert objects as well.

### File and line

| Source of the resource | What is shown |
|------------------------|---------------|
| A YAML file | The file and the line |
| A Helm chart | The template file. The line is shown only if the template contains no template actions (`{{`), because otherwise the rendered output no longer matches the file, and Kubescape prefers no line to a wrong one |
| A Kustomize directory | The directory only. The output is composed from a base and overlays, so no single source line exists |
| A live cluster | No file or line |
| Any source, with `--hide` or `--encrypt` | The path and value, but no line. Source paths are replaced by pseudonyms and cannot be read, and Kubescape warns about it |

### Redaction and scrubbing

Evidence is meant to be shared, so values are redacted by default. `--show-secrets` shows them instead, but where it takes effect depends on the output:

| Output | Effect of `--show-secrets` |
|--------|----------------------------|
| Terminal | Reveals redacted values wherever paths are printed: with `--show-evidence`, and in the control view (`--view control`) also with `--verbose`. On its own it changes nothing |
| SARIF, HTML, CSV and GitLab SAST | Reveals them on its own. `--show-evidence` is not needed |
| JSON | None. The `evidence` array always omits credential-shaped values, and fix values are never redacted (see [Values](#values)) |

A report made with `--show-secrets` contains real values, so check it before sharing it.

A value is redacted when:

- the resource is a `Secret` and the path is under `data` or `stringData`;
- the path is the `value` of a container environment variable;
- the final name of the field, ignoring case and the characters `_`, `-`, `.` and space, contains `password`, `passwd`, `pwd`, `secret`, `token`, `apikey`, `accesskey`, `privatekey`, `credential`, `databaseurl`, `dburl`, `redisurl`, `mongouri`, `mongodburi`, `dsn` or `connectionstring`.

A few Kubernetes fields whose names contain one of these words but hold no credential, such as `automountServiceAccountToken`, are exempt at their documented location.

A redacted value is printed as `[redacted]`. The JSON `evidence` array leaves such entries out, whatever flags are set. For C-0012 in the first example it lists only the variable's name:

```json
"evidence": [{"path": "spec.containers[0].env[1].name", "value": "DB_PASSWORD"}]
```

Redaction goes mainly by field name and by a few known locations. A rule that points at a free-form field should not assume a credential inside it will be hidden.

Separately, before results are printed, Kubescape overwrites the contents of some fields with the text `XXXXXX`, so that scan results do not carry them: `data` and `stringData` of a `Secret`, `data` and `binaryData` of a `ConfigMap`, and the `value` of every environment variable in a container, init container or ephemeral container. A path that points inside these fields can only ever show `XXXXXX`, with or without `--show-secrets`.

This has a consequence for rules. C-0012 emits two paths for a hardcoded variable: the variable's `name` and its `value`. The name path is the one that tells the user which variable to look at. When a rule's finding is a credential, emit a path to the field that names it.

Two flags interact with evidence, and Kubescape prints a warning for each:

- `--hide` and `--encrypt` remove line numbers, as above.
- `--omit-raw-resources` keeps the scanned resources out of the report, but evidence reads those same resources, so field values still reach the terminal. In v1 JSON it does not keep every resource out, as described under [Values](#values).

---

## Ways Evidence Goes Missing

None of these produce an error. The control fails as usual, and the evidence is incomplete or points to the wrong place.

| Pattern | What happens | Example |
|---------|--------------|---------|
| The path is only in `failedPaths` | Not read, so the finding has no evidence | `duplicate-env-var` builds its alert with `"failedPaths": [path], "fixPaths": []` |
| The rule emits no path at all | The control fails and names the resource, with nothing to point at | `naked-pods` (C-0073) emits `"failedPaths": [], "fixPaths": []`. On the example Pod, C-0030, C-0073 and C-0260 fail with no path of any kind |
| Only a fix path, for a field that is absent | The path and the wanted value are shown, at the enclosing block's line. There is no current value, because there is none | `immutable-container-filesystem` (C-0017) |
| Some `deny` blocks have paths and others do not | Evidence appears for some resource shapes only | The ephemeral-container block of `immutable-container-filesystem` emits `"fixPaths": []`, while its Pod and init-container blocks emit a fix path |
| The path is written for the wrong kind | A nearby line, no value | See [A wrong root does not fail loudly](#a-wrong-root-does-not-fail-loudly) |
| The path is malformed | No line, and no value from the resource | `spec.containers[*].image` |
| An index is left unsubstituted | No line, and no value from the resource | `spec.containers[container_ndx].image` |
| The value was scrubbed | `XXXXXX` is shown, or the entry is left out | A path into a ConfigMap's `data` |
| The resource comes from a templated Helm file | The path, but no line | A template containing `{{ .Values.x }}` |

---

## Testing Your Rule

Run the rule against a manifest that makes it fail, and read the evidence column. A custom rule is loaded together with a control:

```
kubescape scan control C-0041 pod.yaml --custom-rules ./my-rules --show-evidence
```

`./my-rules` can hold a bare `.rego` file, or a rule directory with `raw.rego` and `rule.metadata.json`. For each path in the output, check that:

- a path to a field that exists points at that field's own line, not at an enclosing block (a fix path to a field that has to be added is the exception: it points at the enclosing block by design, see [absent fields](#absent-fields));
- a review path shows `(current: ...)`;
- a fix path shows the value the policy requires;
- no `XXXXXX` stands in for something the user needs to read.

A Pod and a Deployment need different roots, so test every kind the rule covers.

---

## Checklist

- [ ] Every `deny` block that can fail a resource emits at least one of `deletePaths`, `reviewPaths` or `fixPaths`.
- [ ] Nothing depends on `failedPaths`.
- [ ] Each path is written for the kind its `deny` block matches, starting at that resource's root.
- [ ] Indexes are substituted with the loop variable, and there are no wildcards.
- [ ] A field that must be added is a `fixPaths` entry with its value. A field that is wrong is a `reviewPaths` or `deletePaths` entry.
- [ ] If the finding is a credential, a path to the field that names it is emitted as well as the one to its value.
- [ ] No `fixPaths` value contains a credential. Fix values are copied into JSON reports as written.
- [ ] The rule was run with `--show-evidence` against a manifest, and each path shows the expected line.

---

## See Also

- [Evidence of Finding proposal](https://github.com/kubescape/designs-and-proposals/blob/main/proposals/evidence-of-finding.md)
- [kubescape-evidence-coverage](https://github.com/PriyanshuKholiya/kubescape-evidence-coverage): a reproducible survey of which regolibrary rules emit evidence paths
- [CLI Reference](cli-reference.md) for `--show-evidence`, `--show-secrets`, `--hide` and `--encrypt`
