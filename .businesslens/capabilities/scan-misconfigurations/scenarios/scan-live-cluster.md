---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User starts a scan of the cluster in the current kube context
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product loads the default frameworks, their controls, the exceptions and the control configuration
    kind: product
    actor: user
    entities:
      - { entity: framework, effect: reads, facts: [Name, Controls] }
      - { entity: control, effect: reads, facts: [Control ID, Severity] }
      - { entity: exception, effect: reads, facts: [Action, Controls, Resources, Expiry] }
      - { entity: control-configuration, effect: reads, facts: [Inputs] }
    contexts: { cli: { place: cli } }
  - text: The Product evaluates each collected Workload and other cluster resource against every control
    kind: product
    actor: user
    entities:
      - { entity: workload, effect: reads, facts: [Kind, Name, Namespace, Configuration] }
      - { entity: control, effect: reads, facts: [Control ID] }
    contexts: { cli: { place: cli } }
  - text: The Product prints the Scan report with its compliance and coverage scores
    kind: product
    actor: user
    entities:
      - { entity: scan-report, effect: creates, to: Plain, facts: [Scanned target, Frameworks, Control results, Resource results, Compliance score, Scan coverage score, Policy degradations] }
    contexts: { cli: { place: cli } }
---

# Scan the live cluster

## Trigger

The User wants to know the security posture of the cluster they are connected
to.

## Outcome

The scan report shows each control's status and the failing resources, the
compliance score and the scan coverage score. The command succeeds unless a
severity or coverage threshold the User set is crossed.

## Edge cases

- A severity threshold fails the command when any failed control is at or above it.
- A coverage threshold fails the command when the scan coverage score is below it.
- The User can also fail the command whenever exceptions or control configuration were served from a fallback source.
- With incremental scanning, resources unchanged since the last incremental scan reuse their cached results, kept in the incremental scan cache.
- When the cluster serves admission policies and the credentials may read them, the report shows which controls a Kubescape admission policy already enforces or audits there.
- Host data from node agents is used when the cluster has the node-agent host data resources, unless the User turns host scanning off.
- Each webhook URL the User names receives the scan summary; a delivery failure is only a warning.
- With an OpenTelemetry endpoint set, the scan's traces and metrics are exported to it.
- Downloaded artifacts can be used instead of downloading, for offline scanning.
