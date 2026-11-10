package fixhandler

import (
	"strconv"
	"strings"

	"github.com/sergi/go-diff/diffmatchpatch"
)

// diffContextLines is how many unchanged lines surround each change in a hunk,
// the default of `diff -u` and `git diff`.
const diffContextLines = 3

const noNewlineMarker = "\\ No newline at end of file\n"

type diffLine struct {
	op   diffmatchpatch.Operation
	text string // without the trailing newline
	// noEOL marks the last line of a file that has no newline after it.
	noEOL bool
	// oldLine and newLine are the 1-based numbers of the line in each file; the
	// one for a file the line is not part of is the count of lines before it.
	oldLine, newLine int
}

// unifiedDiff returns the unified diff that turns oldContent into newContent
// for the file at name, in the form `git apply` and `patch -p1` accept, or ""
// when the two are equal. name is a slash-separated path relative to the
// directory the patch is applied from; it is given the a/ and b/ prefixes.
//
// The diff is by line, so a change inside a line replaces the whole line. A
// file with no newline at its end is marked, as diff does, so the patch
// reproduces the file byte for byte. The diff is not guaranteed to be the
// shortest one: the line diff is cut off after a short time on very large
// inputs, which costs size, never correctness.
func unifiedDiff(name, oldContent, newContent string) string {
	if oldContent == newContent {
		return ""
	}
	lines := diffLines(oldContent, newContent)

	var out strings.Builder
	oldName, newName := patchFileName("a/"+name), patchFileName("b/"+name)
	out.WriteString("diff --git " + oldName + " " + newName + "\n")
	out.WriteString("--- " + oldName + patchNameTerminator(name) + "\n")
	out.WriteString("+++ " + newName + patchNameTerminator(name) + "\n")

	for _, hunk := range diffHunks(lines) {
		writeHunk(&out, hunk)
	}
	return out.String()
}

// diffLines runs a line diff and numbers every line of the result.
func diffLines(oldContent, newContent string) []diffLine {
	dmp := diffmatchpatch.New()
	oldChars, newChars, lineArray := dmp.DiffLinesToChars(oldContent, newContent)
	diffs := dmp.DiffCharsToLines(dmp.DiffMain(oldChars, newChars, false), lineArray)

	var lines []diffLine
	oldLine, newLine := 0, 0
	for _, d := range diffs {
		for _, text := range splitLines(d.Text) {
			line := diffLine{op: d.Type, text: strings.TrimSuffix(text, "\n"), noEOL: !strings.HasSuffix(text, "\n")}
			switch d.Type {
			case diffmatchpatch.DiffDelete:
				oldLine++
			case diffmatchpatch.DiffInsert:
				newLine++
			default:
				oldLine++
				newLine++
			}
			line.oldLine, line.newLine = oldLine, newLine
			lines = append(lines, line)
		}
	}
	return lines
}

// splitLines splits s after each newline, keeping the newlines, so the last
// element lacks one exactly when s does not end with one.
func splitLines(s string) []string {
	var lines []string
	for len(s) > 0 {
		end := strings.IndexByte(s, '\n') + 1
		if end == 0 {
			end = len(s)
		}
		lines = append(lines, s[:end])
		s = s[end:]
	}
	return lines
}

// diffHunks groups the changes with their context. Two changes whose context
// would touch or overlap share a hunk.
func diffHunks(lines []diffLine) [][]diffLine {
	var hunks [][]diffLine
	start := -1 // first line of the hunk being built, context included
	lastChange := -1
	flush := func() {
		if start < 0 {
			return
		}
		end := min(lastChange+diffContextLines+1, len(lines))
		hunks = append(hunks, lines[start:end])
		start = -1
	}
	for i, line := range lines {
		if line.op == diffmatchpatch.DiffEqual {
			continue
		}
		if start >= 0 && i-lastChange-1 > 2*diffContextLines {
			flush()
		}
		if start < 0 {
			start = max(i-diffContextLines, 0)
		}
		lastChange = i
	}
	flush()
	return hunks
}

func writeHunk(out *strings.Builder, hunk []diffLine) {
	var oldCount, newCount int
	for _, line := range hunk {
		if line.op != diffmatchpatch.DiffInsert {
			oldCount++
		}
		if line.op != diffmatchpatch.DiffDelete {
			newCount++
		}
	}
	first := hunk[0]
	out.WriteString("@@ -" + hunkRange(first.oldLine, first.op != diffmatchpatch.DiffInsert, oldCount) +
		" +" + hunkRange(first.newLine, first.op != diffmatchpatch.DiffDelete, newCount) + " @@\n")

	for _, line := range hunk {
		switch line.op {
		case diffmatchpatch.DiffDelete:
			out.WriteString("-")
		case diffmatchpatch.DiffInsert:
			out.WriteString("+")
		default:
			out.WriteString(" ")
		}
		out.WriteString(line.text + "\n")
		if line.noEOL {
			out.WriteString(noNewlineMarker)
		}
	}
}

// hunkRange formats the start,count of one side of a hunk header. first is the
// number of the hunk's first line on that side, and inFile reports whether
// that line is part of the side at all; if not, first is the count of lines
// before it. An empty side starts at the line before the hunk, which is 0 at
// the top of the file.
func hunkRange(first int, inFile bool, count int) string {
	if count == 0 {
		return strconv.Itoa(first) + ",0"
	}
	start := first
	if !inFile {
		start++ // first is the count of lines before it, not its own number
	}
	return strconv.Itoa(start) + "," + strconv.Itoa(count)
}

// patchFileName quotes a path the way git does when it holds a character that
// would break the header line.
func patchFileName(name string) string {
	if !strings.ContainsAny(name, "\"\\\n\r\t") && !hasControl(name) {
		return name
	}
	var quoted strings.Builder
	quoted.WriteByte('"')
	for i := 0; i < len(name); i++ {
		switch c := name[i]; c {
		case '"', '\\':
			quoted.WriteByte('\\')
			quoted.WriteByte(c)
		case '\n':
			quoted.WriteString(`\n`)
		case '\r':
			quoted.WriteString(`\r`)
		case '\t':
			quoted.WriteString(`\t`)
		default:
			if c < 0x20 || c == 0x7f {
				quoted.WriteString("\\" + strconv.FormatInt(int64(c)+0o1000, 8)[1:])
			} else {
				quoted.WriteByte(c)
			}
		}
	}
	quoted.WriteByte('"')
	return quoted.String()
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// patchNameTerminator is the tab diff puts after a file name holding a space,
// which marks where the name ends.
func patchNameTerminator(name string) string {
	if strings.Contains(name, " ") {
		return "\t"
	}
	return ""
}
