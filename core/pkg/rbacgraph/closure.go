package rbacgraph

// EscalationResult is the outcome of computing every RBAC escalation
// technique reachable from a starting Subject.
type EscalationResult struct {
	Start Subject
	// Reached lists every other concrete identity Start can assume, each
	// with the (shortest, breadth-first) chain of edges that reaches it.
	// Truncated as soon as ClusterAdmin is confirmed true (see that
	// field's doc comment) -- it is not a complete enumeration in that
	// case, since every further reach is implied and not worth the noise.
	Reached []EscalationPath
	// Unbounded lists every distinct escalation edge encountered anywhere
	// in the closure that grants everything within some scope rather than
	// a specific enumerable rule set, together with the subject that holds
	// it -- deduplicated by (subject, primitive, detail), since the same
	// grant can otherwise be rediscovered on more than one BFS pass over
	// the same subject.
	Unbounded []UnboundedFinding
	// EffectiveRules is the union of every ScopedRule reachable: Start's
	// own direct rules, every rule granted via bind-verb/escalate-verb
	// (including transitively, when a granted Role/ClusterRole itself
	// grants further escalation), and every rule directly held by each
	// identity in Reached. Also truncated once ClusterAdmin is confirmed.
	EffectiveRules []ScopedRule
	// ClusterAdmin is true when EffectiveRules includes a cluster-wide
	// */*/* rule, an Unbounded finding covers the whole cluster
	// (Scope == ""), or a superuser group (system:masters) was reached via
	// impersonation -- however it was actually reached. Once true, the BFS
	// stops expanding further: cluster-admin-equivalent power already
	// implies every other identity and permission is reachable, so
	// continuing would only enumerate implied consequences (e.g. every
	// ServiceAccount in the cluster, since cluster-admin can always
	// assign-serviceaccount to any of them) rather than surface anything
	// new -- Reached/EffectiveRules reflect whatever had already been
	// discovered at the point this became true, not a complete picture.
	// This early stop is always sound: the verdict it produces is never
	// wrong, only arrived at before every consequence was enumerated.
	ClusterAdmin bool
	// Truncated is true when the search hit maxEscalationHops with
	// ClusterAdmin still false and work still queued -- meaning this
	// result may be an incomplete negative, not a confirmed one. This is
	// the failure mode that actually matters: unlike the ClusterAdmin
	// early-stop (always a sound true), running out of budget without
	// reaching a verdict means a real escalation path may exist beyond
	// what was explored. Distinguish this from a genuine "nothing found"
	// before treating ClusterAdmin == false as a clean bill of health.
	Truncated bool
}

// UnboundedFinding records that Subject holds an unrestricted escalation
// primitive whose targets this package cannot enumerate from collected
// cluster objects (e.g. impersonate on users with no resourceNames
// restriction, or escalate+update on clusterroles cluster-wide).
type UnboundedFinding struct {
	Subject Subject
	Edge    EscalationEdge
}

// maxEscalationHops bounds the BFS worklist: subjects dequeued and
// processed, not raw hop-count. Deliberately generous -- a single
// cluster-wide "create pods" grant alone enqueues every ServiceAccount in
// the cluster (routine on any cluster with hundreds of Service Accounts
// across an ingress/operator stack), so a tight bound here risks exactly
// the false-negative failure mode this package exists to avoid: a result
// that looks like a clean negative because the search ran out of budget,
// not because there was nothing to find. See EscalationResult.Truncated.
var maxEscalationHops = 20000 // var, not const: tests override this to exercise Truncated without building a 20000-object fixture.

// AnalyzeEscalation computes every privilege-escalation technique reachable
// from start via breadth-first search: assuming another concrete identity
// (impersonate, assign-serviceaccount, mint-serviceaccount-token) queues
// that identity for its own escalation edges to be explored in turn;
// adopting a Role/ClusterRole's rules (bind-verb, escalate-verb) enriches
// the current subject's own rule set and re-queues it, so a rule gained
// that way which itself unlocks further escalation (e.g. a bound
// ClusterRole that grants impersonate) is chased, not just recorded.
// Reprocessing a subject happens only when a bind/escalate edge actually
// grants something new (tracked per-subject, keyed by the edge's Detail
// string, which is unique per distinct Role/ClusterRole+scope grant), so
// this always terminates even though maxEscalationHops bounds it too.
// Reaching a hardcoded superuser identity (system:masters) via
// impersonation, or confirming cluster-admin-equivalent power any other
// way, stops the search early -- see EscalationResult.ClusterAdmin and
// EscalationResult.Truncated for what that does and doesn't mean.
func (idx *Index) AnalyzeEscalation(start Subject) EscalationResult {
	subjectRules := map[Subject][]ScopedRule{start: idx.DirectRules(start)}
	grantedSeen := map[Subject]map[string]bool{start: {}}
	unboundedSeen := map[string]bool{}
	pathTo := map[Subject][]EscalationEdge{}
	visited := map[Subject]bool{start: true}
	var order []Subject
	var unbounded []UnboundedFinding
	clusterAdmin := IsClusterAdminEquivalent(subjectRules[start]) || superuserGroups[start.Name] && start.Kind == KindGroup

	worklist := []Subject{start}
	truncated := false
	for i := 0; len(worklist) > 0 && !clusterAdmin; i++ {
		if i >= maxEscalationHops {
			truncated = true
			break
		}
		s := worklist[0]
		worklist = worklist[1:]

		edges := idx.DirectEscalationEdges(s, subjectRules[s])
		grew := false
		for _, e := range edges {
			switch {
			case e.ToSubject != nil:
				t := *e.ToSubject
				if t.Kind == KindGroup && superuserGroups[t.Name] {
					clusterAdmin = true
					pathTo[t] = append(append([]EscalationEdge{}, pathTo[s]...), e)
					if !visited[t] {
						visited[t] = true
						order = append(order, t)
					}
					break
				}
				if visited[t] {
					continue
				}
				visited[t] = true
				order = append(order, t)
				pathTo[t] = append(append([]EscalationEdge{}, pathTo[s]...), e)
				subjectRules[t] = idx.DirectRules(t)
				grantedSeen[t] = map[string]bool{}
				worklist = append(worklist, t)
			case e.Unbounded:
				key := string(s.Kind) + "/" + s.Namespace + "/" + s.Name + "|" + string(e.Primitive) + "|" + e.Detail
				if !unboundedSeen[key] {
					unboundedSeen[key] = true
					unbounded = append(unbounded, UnboundedFinding{Subject: s, Edge: e})
				}
				if e.Scope == "" {
					clusterAdmin = true
				}
			default:
				if grantedSeen[s][e.Detail] {
					continue
				}
				grantedSeen[s][e.Detail] = true
				subjectRules[s] = append(subjectRules[s], e.GrantedRules...)
				grew = true
			}
			if clusterAdmin {
				break
			}
		}
		if grew && !clusterAdmin {
			if IsClusterAdminEquivalent(subjectRules[s]) {
				clusterAdmin = true
			} else {
				worklist = append(worklist, s)
			}
		}
	}

	allRules := append([]ScopedRule{}, subjectRules[start]...)
	var reached []EscalationPath
	for _, s := range order {
		allRules = append(allRules, subjectRules[s]...)
		reached = append(reached, EscalationPath{From: start, Edges: pathTo[s]})
	}

	if !clusterAdmin {
		clusterAdmin = IsClusterAdminEquivalent(allRules)
	}
	if clusterAdmin {
		truncated = false
	}

	return EscalationResult{
		Start:          start,
		Reached:        reached,
		Unbounded:      unbounded,
		EffectiveRules: allRules,
		ClusterAdmin:   clusterAdmin,
		Truncated:      truncated,
	}
}
