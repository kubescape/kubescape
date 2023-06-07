package hostsensorutils

import "sync"

type LogsMap struct {
	// use sync.Mutex to avoid read/write
	// access issues in multi-thread environments.
	sync.Mutex
	usedLogs map[string]int
}

// NewLogCoupling return an empty LogsMap struct ready to be used.
func NewLogCoupling() *LogsMap {
	return &LogsMap{
		usedLogs: make(map[string]int),
	}
}

// update add the logContent to the internal map
// and set the occurrencty to 1 (if it has never been used before),
// increment its values otherwise.
func (lm *LogsMap) update(logContent string) {
	lm.Lock()
	_, ok := lm.usedLogs[logContent]
	if !ok {
		lm.usedLogs[logContent] = 1
	} else {
		lm.usedLogs[logContent]++
	}
	lm.Unlock()
}

// isDuplicated check if logContent is already present inside the internal map.
// Return true in case logContent already exists, false otherwise.
func (lm *LogsMap) isDuplicated(logContent string) bool {
	lm.Lock()
	_, ok := lm.usedLogs[logContent]
	lm.Unlock()
	return ok
}

// GgtOccurrence retrieve the number of occurrences logContent has been used.
func (lm *LogsMap) getOccurrence(logContent string) int {
	lm.Lock()
	occurrence, ok := lm.usedLogs[logContent]
	lm.Unlock()
	if !ok {
		return 0
	}
	return occurrence
}
