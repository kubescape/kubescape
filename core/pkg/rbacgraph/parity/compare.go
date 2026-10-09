package parity

import "fmt"

// Compare applies the parity rule to one question, given what Kubernetes and
// rbacgraph each answer:
//
//   - They agree and no difference is recorded: nil.
//   - They differ and the question records an intentionalDifference: nil.
//   - They differ and nothing is recorded: an error. Either rbacgraph is
//     wrong, or the difference is deliberate and has to be written down.
//   - They agree but a difference is still recorded: an error. A stale entry
//     would otherwise hide the next real difference on that question.
func Compare(fixture string, q Question, kubernetes, kubescape Answer) error {
	differ := kubernetes != kubescape
	switch {
	case differ && q.IntentionalDifference == nil:
		return fmt.Errorf("fixture %q, question %q: %s\n\tKubernetes: %s\n\tKubescape:  %s\n\tthe difference is not documented: fix rbacgraph, or record an intentionalDifference with its reason",
			fixture, q.ID, q, kubernetes, kubescape)
	case !differ && q.IntentionalDifference != nil:
		return fmt.Errorf("fixture %q, question %q: %s\n\tKubernetes: %s\n\tKubescape:  %s\n\tan intentionalDifference is recorded (%q) but the two now agree: remove it",
			fixture, q.ID, q, kubernetes, kubescape, q.IntentionalDifference.Reason)
	}
	return nil
}

// CheckRecorded holds the answer a fixture records for Kubernetes to what a
// real kube-apiserver said. serverVersion is the server's gitVersion.
func CheckRecorded(fixture string, q Question, live Answer, serverVersion string) error {
	if q.Kubernetes == live {
		return nil
	}
	return fmt.Errorf("fixture %q, question %q: %s\n\trecorded Kubernetes answer: %s\n\tkube-apiserver %s:      %s\n\tthe recorded answer is wrong for this Kubernetes version: correct the fixture",
		fixture, q.ID, q, q.Kubernetes, serverVersion, live)
}
