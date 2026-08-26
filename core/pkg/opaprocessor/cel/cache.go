package cel

import (
	"sync"

	"github.com/google/cel-go/cel"
)

// programCache memoizes compiled CEL programs by expression text. Compiling an
// expression is the expensive step; running the compiled program is cheap. A
// scan evaluates the same bundle expressions against every scanned object, so
// without the cache a 1000-object scan would recompile each expression 1000
// times.
//
// Compile failures are cached too: a broken expression stays broken no matter
// which object it runs against, so its error is stored and served on every
// later lookup instead of reattempting the compile per object. Eval failures
// are the opposite — they depend on the object being evaluated (a field
// missing on one object can be present on the next) — so they must never land
// in the cache. That holds by construction: the cache stores programs, and
// evaluation happens on the caller's side of the lookup.
type programCache struct {
	// compile builds a runnable program for one expression. Injected so tests
	// can count invocations; the Evaluator wires in its env-backed compile.
	compile func(expr string) (cel.Program, error)

	mu      sync.Mutex
	entries map[string]*programCacheEntry
}

// programCacheEntry is one memoized compile outcome. The entry's Once runs the
// compile outside the cache lock, so a slow compile of one expression does not
// block lookups of others, while concurrent lookups of the same expression
// still compile it exactly once.
type programCacheEntry struct {
	once sync.Once
	prog cel.Program
	err  error
}

func newProgramCache(compile func(expr string) (cel.Program, error)) *programCache {
	return &programCache{
		compile: compile,
		entries: make(map[string]*programCacheEntry),
	}
}

// get returns the compiled program for an expression, compiling it on the
// first lookup and serving the memoized program (or compile error) afterwards.
func (c *programCache) get(expr string) (cel.Program, error) {
	c.mu.Lock()
	entry, ok := c.entries[expr]
	if !ok {
		entry = &programCacheEntry{}
		c.entries[expr] = entry
	}
	c.mu.Unlock()

	entry.once.Do(func() {
		entry.prog, entry.err = c.compile(expr)
	})
	return entry.prog, entry.err
}
