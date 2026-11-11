package opaprocessor

import (
	"regexp"
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	corev1 "k8s.io/api/core/v1"
)

const redactedValue = "XXXXXX"

var (
	secretNamePattern = regexp.MustCompile(`password|passwd|secret|token|api[-_.]?key|access[-_.]?key|private[-_.]?key|credential`)

	// Names like --token-auth-file or --tls-secret-name carry a path, a
	// setting or a reference, not the secret itself.
	nonSecretNameSuffix = regexp.MustCompile(`[-_.](file|path|dir|name|ttl|expiration|lifetime|duration)$`)

	// The password in scheme://user:password@host. The password may itself
	// contain '@', so it runs to the last '@' before the path, query or fragment.
	urlPasswordPattern = regexp.MustCompile(`(://[^/?#\s:@]*:)[^/?#\s]*@`)

	assignmentNamePattern = regexp.MustCompile(`^-{0,2}[A-Za-z_][A-Za-z0-9_.-]*$`)
	headerPattern         = regexp.MustCompile(`^([A-Za-z0-9_-]+):\s*\S`)

	secretHeaders = map[string]struct{}{
		"authorization":       {},
		"proxy-authorization": {},
		"cookie":              {},
		"set-cookie":          {},
	}
)

func isBool(value string) bool {
	return value == "true" || value == "false"
}

func isSecretName(name string) bool {
	name = strings.ToLower(strings.TrimLeft(name, "-"))
	return secretNamePattern.MatchString(name) && !nonSecretNameSuffix.MatchString(name)
}

// isSecretFlag reports whether word is a flag such as --password whose value
// is the next word.
func isSecretFlag(word string) bool {
	return strings.HasPrefix(word, "-") && !strings.Contains(word, "=") && isSecretName(word)
}

func isSecretHeader(name string) bool {
	_, ok := secretHeaders[strings.ToLower(name)]
	return ok || isSecretName(name)
}

func isFlagValue(word string) bool {
	return !strings.HasPrefix(word, "-") && !isBool(word)
}

// redactWord masks the secret part of a single argument: the value of a
// secret NAME=value or --name=value, the value of an "Authorization: ..."
// style header, and the password of a URL.
func redactWord(word string) string {
	if m := headerPattern.FindStringSubmatch(word); m != nil && isSecretHeader(m[1]) {
		return m[1] + ": " + redactedValue
	}
	if name, value, ok := strings.Cut(word, "="); ok && assignmentNamePattern.MatchString(name) {
		if value != "" && !isBool(value) && isSecretName(name) {
			return name + "=" + redactedValue
		}
		if value != "" {
			return name + "=" + redactArg(value)
		}
	}
	return redactURLPasswords(word)
}

// redactURLPasswords masks URL passwords before any shell splitting, since a
// password may contain ;, & or | that would otherwise break the URL apart.
func redactURLPasswords(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	return urlPasswordPattern.ReplaceAllString(s, "${1}"+redactedValue+"@")
}

// isQuoted reports whether a raw shell word starts with a quote, which makes
// a leading '-' part of a value rather than a flag.
func isQuoted(raw string) bool {
	return raw != "" && (raw[0] == '"' || raw[0] == '\'')
}

// redactArg masks secrets in one argv element. A flag, a header or a
// NAME=value assignment is a single value even when it contains spaces;
// any other element with whitespace is treated as a shell script.
func redactArg(arg string) string {
	arg = redactURLPasswords(arg)
	if strings.HasPrefix(arg, "-") || headerPattern.MatchString(arg) || isAssignment(arg) || !strings.ContainsAny(arg, shellSeparators) {
		return redactWord(arg)
	}
	return redactShell(arg)
}

func isAssignment(arg string) bool {
	name, _, ok := strings.Cut(arg, "=")
	return ok && assignmentNamePattern.MatchString(name)
}

// redactShell masks secrets in a shell script, word by word, so that quoted
// values with spaces or escaped quotes are masked whole. The script passed to
// a -c flag, as in sh -c 'TOKEN=x && ./run', is redacted as a script itself.
func redactShell(script string) string {
	script = redactURLPasswords(script)
	var b strings.Builder
	last := 0
	pendingSecret, pendingScript := false, false
	for _, span := range shellWords(script) {
		raw := script[span[0]:span[1]]
		word := shellUnquote(raw)
		redacted := raw
		var masked string
		switch {
		case pendingSecret && (isFlagValue(word) || isQuoted(raw) && !isBool(word)):
			masked = redactedValue
		case pendingScript:
			masked = redactShell(word)
		default:
			masked = redactArg(word)
		}
		if masked != word {
			redacted = masked
			if masked != redactedValue && isQuoted(raw) {
				redacted = raw[:1] + masked + raw[:1]
			}
		}
		pendingSecret, pendingScript = isSecretFlag(word), isScriptFlag(word)
		b.WriteString(script[last:span[0]])
		b.WriteString(redacted)
		last = span[1]
	}
	b.WriteString(script[last:])
	return b.String()
}

// shellSeparators end an unquoted shell word: whitespace and the ;, & and |
// of command lists and pipelines.
const shellSeparators = " \t\n;&|"

// shellWords splits script on unquoted separators and returns the byte span
// of each word. Quotes and backslash escapes are kept inside the word.
func shellWords(script string) [][2]int {
	var spans [][2]int
	start := -1
	var quote byte
	for i := 0; i < len(script); i++ {
		c := script[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\':
			if start < 0 {
				start = i
			}
			i++
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case strings.IndexByte(shellSeparators, c) >= 0:
			if start >= 0 {
				spans = append(spans, [2]int{start, i})
				start = -1
			}
		default:
			if start < 0 {
				start = i
			}
			if c == '"' || c == '\'' {
				quote = c
			}
		}
	}
	if start >= 0 {
		spans = append(spans, [2]int{start, len(script)})
	}
	return spans
}

// shellUnquote removes the quoting from a shell word.
func shellUnquote(word string) string {
	var b strings.Builder
	var quote byte
	for i := 0; i < len(word); i++ {
		c := word[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
				continue
			}
		case c == '\\' && i+1 < len(word):
			i++
			c = word[i]
		case c == '"' || c == '\'':
			if quote == c {
				quote = 0
				continue
			}
			if quote == 0 {
				quote = c
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// redactCommandLine masks secrets across parts as one argv, so a flag at the
// end of command still applies to the value that starts args.
func redactCommandLine(parts ...[]string) {
	pendingSecret, pendingScript := false, false
	for _, argv := range parts {
		for i, arg := range argv {
			switch {
			case pendingSecret && isFlagValue(arg):
				argv[i] = redactedValue
			case pendingScript:
				argv[i] = redactShell(arg)
			default:
				argv[i] = redactArg(arg)
			}
			pendingSecret, pendingScript = isSecretFlag(arg), isScriptFlag(arg)
		}
	}
}

// isScriptFlag reports whether word is a short flag group ending in c, such
// as the -c, -ec or -lc that hand a script to sh, bash or su.
func isScriptFlag(word string) bool {
	if len(word) < 2 || word[0] != '-' || !strings.HasSuffix(word, "c") {
		return false
	}
	for _, c := range word[1:] {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

func redactHTTPHeaders(action *corev1.HTTPGetAction) {
	if action == nil {
		return
	}
	for i := range action.HTTPHeaders {
		if isSecretHeader(action.HTTPHeaders[i].Name) {
			action.HTTPHeaders[i].Value = redactedValue
		}
	}
}

func redactExec(action *corev1.ExecAction) {
	if action != nil {
		redactCommandLine(action.Command)
	}
}

func redactLifecycleHandler(handler *corev1.LifecycleHandler) {
	if handler != nil {
		redactExec(handler.Exec)
		redactHTTPHeaders(handler.HTTPGet)
	}
}

func redactContainerSecrets(command, args []string, lifecycle *corev1.Lifecycle, probes ...*corev1.Probe) {
	redactCommandLine(command, args)
	if lifecycle != nil {
		redactLifecycleHandler(lifecycle.PostStart)
		redactLifecycleHandler(lifecycle.PreStop)
	}
	for _, probe := range probes {
		if probe != nil {
			redactExec(probe.Exec)
			redactHTTPHeaders(probe.HTTPGet)
		}
	}
}

// redactAnnotations masks annotation values whose key looks like it names a
// secret, on the object itself and on its pod template.
func redactAnnotations(workload workloadinterface.IWorkload) {
	obj := workload.GetObject()
	paths := [][]string{{"metadata", "annotations"}}
	if podMetadata := workloadinterface.PodMetadata(workload.GetKind()); len(podMetadata) > 1 {
		paths = append(paths, append(podMetadata, "annotations"))
	}
	for _, path := range paths {
		raw, ok := workloadinterface.InspectMap(obj, path...)
		if !ok {
			continue
		}
		annotations, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for key, value := range annotations {
			name := key[strings.LastIndex(key, "/")+1:]
			if v, ok := value.(string); ok && !isBool(v) && isSecretName(name) {
				annotations[key] = redactedValue
			}
		}
	}
}
