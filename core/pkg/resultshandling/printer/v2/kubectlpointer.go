package printer

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/pathparse"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	v2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// A scan of a live cluster has no manifest to point into, so its evidence
// carries no file and no line. What the user can still do is look at the field
// on the cluster, and this file builds the command for that:
//
//	kubectl get deployment.apps demo -n default -o jsonpath='{.spec.template.spec.hostNetwork}'

// kubectlName matches a Kubernetes name, namespace, kind or API group: the
// characters a DNS label or subdomain allows. Anything else is left out of a
// command rather than quoted into it, because these values come from the scanned
// resource and end up on a shell command line.
var kubectlName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// shellWordSafe matches a word that needs no quoting in a POSIX shell.
var shellWordSafe = regexp.MustCompile(`^[A-Za-z0-9._/@:=+-]+$`)

// isClusterScan reports whether the scan read its resources from a live
// cluster, as opposed to manifest files, a Helm chart or a repository.
func isClusterScan(opaSessionObj *cautils.OPASessionObj) bool {
	return opaSessionObj != nil && opaSessionObj.Metadata != nil &&
		opaSessionObj.Metadata.ScanMetadata.ScanningTarget == v2.Cluster
}

// jsonPathExpr turns a parsed path into the JSONPath expression kubectl reads
// with -o jsonpath, or reports false when the path has no spelling in it.
//
// A key is written after a dot, with a backslash before every character that
// is not a letter, a digit, "_" or "-". kubectl's JSONPath parser treats a
// backslash as an escape for whatever follows and drops it, which is how a key
// holding dots or slashes, such as the label app.kubernetes.io/name, is
// written. A key that holds a backslash or a control character cannot be
// written that way, so it gets no command.
func jsonPathExpr(segments []pathSegment) (string, bool) {
	if len(segments) == 0 {
		return "", false
	}
	var b strings.Builder
	b.WriteByte('{')
	for _, seg := range segments {
		if seg.Key == "" {
			return "", false
		}
		b.WriteByte('.')
		for _, r := range seg.Key {
			switch {
			case r == '\\' || unicode.IsControl(r):
				return "", false
			case r < unicode.MaxASCII && (r == '_' || r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')):
				b.WriteRune(r)
			default:
				b.WriteByte('\\')
				b.WriteRune(r)
			}
		}
		if seg.Index >= 0 {
			b.WriteString("[" + strconv.Itoa(seg.Index) + "]")
		}
	}
	b.WriteByte('}')
	return b.String(), true
}

// shellQuote wraps s in single quotes for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// shellWord returns s as it can be written on a command line: bare when that is
// safe, quoted otherwise.
func shellWord(s string) string {
	if shellWordSafe.MatchString(s) {
		return s
	}
	return shellQuote(s)
}

// kubectlResource names a kind the way kubectl accepts it: the lower-case kind,
// followed by the API group when there is one, as in deployment.apps. The core
// group has no group part. It reports false when either part is not a plain
// name.
func kubectlResource(apiVersion, kind string) (string, bool) {
	if !kubectlName.MatchString(kind) {
		return "", false
	}
	resource := strings.ToLower(kind)
	if slash := strings.Index(apiVersion, "/"); slash >= 0 {
		group := apiVersion[:slash]
		if !kubectlName.MatchString(group) {
			return "", false
		}
		resource += "." + group
	}
	return resource, true
}

// kubectlGetCommand returns the command that prints the field at path on the
// cluster. kubeContext names the cluster the scan ran against, so the command
// reads the same one even when it is not the current context; empty leaves the
// context out. It reports false when the resource or the path cannot be put on a
// command line safely.
func kubectlGetCommand(resource workloadinterface.IMetadata, kubeContext, path string) (string, bool) {
	segments, err := pathparse.ParsePath(path)
	if err != nil {
		return "", false
	}
	expr, ok := jsonPathExpr(segments)
	if !ok {
		return "", false
	}
	kind, ok := kubectlResource(resource.GetApiVersion(), resource.GetKind())
	if !ok || !kubectlName.MatchString(resource.GetName()) {
		return "", false
	}

	words := []string{"kubectl", "get", kind, resource.GetName()}
	if namespace := resource.GetNamespace(); namespace != "" {
		if !kubectlName.MatchString(namespace) {
			return "", false
		}
		words = append(words, "-n", namespace)
	}
	if kubeContext != "" {
		words = append(words, "--context", shellWord(kubeContext))
	}
	words = append(words, "-o", "jsonpath="+shellQuote(expr))
	return strings.Join(words, " "), true
}

// kubectlPointers returns the commands for the paths that the failed controls
// name on resource, in the order the paths appear and without repeats. A path
// that holds a credential gets no command unless showSecrets is set: the
// command itself is harmless, but evidence is written to be shared, and a line
// that tells a reader how to print a credential does not belong in it.
func kubectlPointers(controls []resourcesresults.ResourceAssociatedControl, summary *reportsummary.SummaryDetails, resource workloadinterface.IMetadata, kubeContext string, showSecrets bool) []string {
	kind := resource.GetKind()
	var commands []string
	seen := map[string]struct{}{}

	add := func(path string) {
		if path == "" {
			return
		}
		if _, done := seen[path]; done {
			return
		}
		seen[path] = struct{}{}
		if !showSecrets && isSensitivePath(kind, path) {
			return
		}
		if command, ok := kubectlGetCommand(resource, kubeContext, path); ok {
			commands = append(commands, command)
		}
	}

	for i := range controls {
		if !cautils.ControlStatus(summary, &controls[i]).IsFailed() {
			continue
		}
		displayed := cautils.EvidenceControl(summary, controls[i])
		for j := range displayed.ResourceAssociatedRules {
			for _, p := range displayed.ResourceAssociatedRules[j].Paths {
				add(p.DeletePath)
				add(p.ReviewPath)
				add(p.FixPath.Path)
			}
		}
	}
	return commands
}
