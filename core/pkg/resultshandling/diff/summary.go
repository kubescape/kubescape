package diff

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

const (
	SummaryJSONFormat = "summary-json"
	SummaryYAMLFormat = "summary-yaml"
	SummaryCSVFormat  = "summary-csv"
)

type Summary struct {
	Total        BucketSummary     `json:"total"`
	Regressions  BucketSummary     `json:"regressions"`
	Buckets      map[string]Bucket `json:"buckets"`
	Severities   []SeveritySummary `json:"severities,omitempty"`
	Controls     []ControlSummary  `json:"controls,omitempty"`
	Resources    []ResourceSummary `json:"resources,omitempty"`
	TopControls  []ControlCounter  `json:"topControls,omitempty"`
	TopResources []ResourceCounter `json:"topResources,omitempty"`
	Warnings     []string          `json:"warnings,omitempty"`
	Threshold    string            `json:"threshold"`
}

type BucketSummary struct {
	New          int `json:"new"`
	Resolved     int `json:"resolved"`
	Unchanged    int `json:"unchanged"`
	Incomparable int `json:"incomparable"`
	Warnings     int `json:"warnings"`
}

type Bucket struct {
	Count      int               `json:"count"`
	Severities []SeverityCounter `json:"severities,omitempty"`
	Controls   []ControlCounter  `json:"controls,omitempty"`
	Resources  []ResourceCounter `json:"resources,omitempty"`
}

type SeveritySummary struct {
	Severity string        `json:"severity"`
	Buckets  BucketSummary `json:"buckets"`
}

type ControlSummary struct {
	ControlID   string        `json:"controlID"`
	ControlName string        `json:"controlName,omitempty"`
	Severity    string        `json:"severity,omitempty"`
	Buckets     BucketSummary `json:"buckets"`
}

type ResourceSummary struct {
	ResourceID string        `json:"resourceID"`
	Buckets    BucketSummary `json:"buckets"`
}

type SeverityCounter struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type ControlCounter struct {
	ControlID   string `json:"controlID"`
	ControlName string `json:"controlName,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Count       int    `json:"count"`
}

type ResourceCounter struct {
	ResourceID string `json:"resourceID"`
	Count      int    `json:"count"`
}

type summaryAccumulator struct {
	total      BucketSummary
	buckets    map[string]*bucketAccumulator
	severities map[string]*severityAccumulator
	controls   map[string]*controlAccumulator
	resources  map[string]*resourceAccumulator
}

type bucketAccumulator struct {
	count      int
	severities map[string]int
	controls   map[string]*controlCounterAccumulator
	resources  map[string]int
}

type severityAccumulator struct {
	severity string
	buckets  BucketSummary
}

type controlAccumulator struct {
	controlID   string
	controlName string
	severity    string
	buckets     BucketSummary
}

type resourceAccumulator struct {
	resourceID string
	buckets    BucketSummary
}

type controlCounterAccumulator struct {
	controlID   string
	controlName string
	severity    string
	count       int
}

func Summarize(cs *ChangeSet, threshold string) Summary {
	acc := newSummaryAccumulator()
	if cs != nil {
		acc.addBucket("new", FilterBySeverity(cs.New, threshold))
		acc.addBucket("resolved", cs.Resolved)
		acc.addBucket("unchanged", cs.Unchanged)
		acc.addBucket("incomparable", FilterBySeverity(cs.Incomparable, threshold))
		acc.total.Warnings = len(cs.Warnings)
	}

	summary := Summary{
		Total:        acc.total,
		Buckets:      acc.bucketSummaries(),
		Severities:   acc.severitySummaries(),
		Controls:     acc.controlSummaries(),
		Resources:    acc.resourceSummaries(),
		TopControls:  acc.topRegressionControls(),
		TopResources: acc.topRegressionResources(),
		Threshold:    thresholdLabel(threshold),
	}
	if cs != nil {
		summary.Warnings = append([]string(nil), cs.Warnings...)
	}
	summary.Regressions = BucketSummary{
		New:          summary.Total.New,
		Incomparable: summary.Total.Incomparable,
		Warnings:     summary.Total.Warnings,
	}
	return summary
}

func PrintSummaryJSON(w io.Writer, cs *ChangeSet, threshold string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(Summarize(cs, threshold))
}

func PrintSummaryYAML(w io.Writer, cs *ChangeSet, threshold string) error {
	data, err := yaml.Marshal(Summarize(cs, threshold))
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func PrintSummaryCSV(w io.Writer, cs *ChangeSet, threshold string) error {
	summary := Summarize(cs, threshold)
	writer := csv.NewWriter(w)
	if err := writeSummaryCSV(writer, summary); err != nil {
		return err
	}
	writer.Flush()
	return writer.Error()
}

func writeSummaryCSV(writer *csv.Writer, summary Summary) error {
	for _, row := range summaryCSVRows(summary) {
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func summaryCSVRows(summary Summary) [][]string {
	rows := [][]string{
		{"section", "key", "bucket", "severity", "control_id", "control_name", "resource_id", "count"},
		{"metadata", "threshold", "", "", "", "", "", summary.Threshold},
		{"metadata", "warnings", "", "", "", "", "", fmt.Sprint(len(summary.Warnings))},
	}
	rows = append(rows, bucketSummaryCSVRows("total", "all", summary.Total)...)
	rows = append(rows, bucketSummaryCSVRows("regressions", "all", summary.Regressions)...)
	for _, bucketName := range []string{"new", "resolved", "unchanged", "incomparable"} {
		bucket := summary.Buckets[bucketName]
		rows = append(rows, []string{"bucket", "total", bucketName, "", "", "", "", fmt.Sprint(bucket.Count)})
		for _, severity := range bucket.Severities {
			rows = append(rows, []string{"bucket_severity", "", bucketName, severity.Severity, "", "", "", fmt.Sprint(severity.Count)})
		}
		for _, control := range bucket.Controls {
			rows = append(rows, []string{"bucket_control", "", bucketName, control.Severity, control.ControlID, control.ControlName, "", fmt.Sprint(control.Count)})
		}
		for _, resource := range bucket.Resources {
			rows = append(rows, []string{"bucket_resource", "", bucketName, "", "", "", resource.ResourceID, fmt.Sprint(resource.Count)})
		}
	}
	for _, severity := range summary.Severities {
		rows = append(rows, bucketSummaryCSVRows("severity", severity.Severity, severity.Buckets)...)
	}
	for _, control := range summary.Controls {
		rows = append(rows, controlSummaryCSVRows(control)...)
	}
	for _, resource := range summary.Resources {
		rows = append(rows, resourceSummaryCSVRows(resource)...)
	}
	for _, control := range summary.TopControls {
		rows = append(rows, []string{"top_control", "", "regressions", control.Severity, control.ControlID, control.ControlName, "", fmt.Sprint(control.Count)})
	}
	for _, resource := range summary.TopResources {
		rows = append(rows, []string{"top_resource", "", "regressions", "", "", "", resource.ResourceID, fmt.Sprint(resource.Count)})
	}
	for _, warning := range summary.Warnings {
		rows = append(rows, []string{"warning", warning, "", "", "", "", "", ""})
	}
	return rows
}

func bucketSummaryCSVRows(section, key string, buckets BucketSummary) [][]string {
	return [][]string{
		{section, key, "new", "", "", "", "", fmt.Sprint(buckets.New)},
		{section, key, "resolved", "", "", "", "", fmt.Sprint(buckets.Resolved)},
		{section, key, "unchanged", "", "", "", "", fmt.Sprint(buckets.Unchanged)},
		{section, key, "incomparable", "", "", "", "", fmt.Sprint(buckets.Incomparable)},
		{section, key, "warnings", "", "", "", "", fmt.Sprint(buckets.Warnings)},
	}
}

func controlSummaryCSVRows(control ControlSummary) [][]string {
	return [][]string{
		{"control", "", "new", control.Severity, control.ControlID, control.ControlName, "", fmt.Sprint(control.Buckets.New)},
		{"control", "", "resolved", control.Severity, control.ControlID, control.ControlName, "", fmt.Sprint(control.Buckets.Resolved)},
		{"control", "", "unchanged", control.Severity, control.ControlID, control.ControlName, "", fmt.Sprint(control.Buckets.Unchanged)},
		{"control", "", "incomparable", control.Severity, control.ControlID, control.ControlName, "", fmt.Sprint(control.Buckets.Incomparable)},
	}
}

func resourceSummaryCSVRows(resource ResourceSummary) [][]string {
	return [][]string{
		{"resource", "", "new", "", "", "", resource.ResourceID, fmt.Sprint(resource.Buckets.New)},
		{"resource", "", "resolved", "", "", "", resource.ResourceID, fmt.Sprint(resource.Buckets.Resolved)},
		{"resource", "", "unchanged", "", "", "", resource.ResourceID, fmt.Sprint(resource.Buckets.Unchanged)},
		{"resource", "", "incomparable", "", "", "", resource.ResourceID, fmt.Sprint(resource.Buckets.Incomparable)},
	}
}

func newSummaryAccumulator() *summaryAccumulator {
	return &summaryAccumulator{
		buckets:    map[string]*bucketAccumulator{},
		severities: map[string]*severityAccumulator{},
		controls:   map[string]*controlAccumulator{},
		resources:  map[string]*resourceAccumulator{},
	}
}

func (a *summaryAccumulator) addBucket(name string, changes []ControlChange) {
	for _, change := range changes {
		a.total.increment(name)
		a.bucket(name).add(change)
		a.severity(change.Severity).buckets.increment(name)
		a.control(change).buckets.increment(name)
		a.resource(change.ResourceID).buckets.increment(name)
	}
}

func (a *summaryAccumulator) bucket(name string) *bucketAccumulator {
	if existing := a.buckets[name]; existing != nil {
		return existing
	}
	bucket := &bucketAccumulator{
		severities: map[string]int{},
		controls:   map[string]*controlCounterAccumulator{},
		resources:  map[string]int{},
	}
	a.buckets[name] = bucket
	return bucket
}

func (a *summaryAccumulator) severity(value string) *severityAccumulator {
	value = normalizedSummaryLabel(value)
	if existing := a.severities[value]; existing != nil {
		return existing
	}
	item := &severityAccumulator{severity: value}
	a.severities[value] = item
	return item
}

func (a *summaryAccumulator) control(change ControlChange) *controlAccumulator {
	id := normalizedSummaryLabel(change.ControlID)
	if existing := a.controls[id]; existing != nil {
		if existing.ControlName() == "" {
			existing.controlName = change.ControlName
		}
		if existing.severity == "" {
			existing.severity = change.Severity
		}
		return existing
	}
	item := &controlAccumulator{
		controlID:   id,
		controlName: change.ControlName,
		severity:    change.Severity,
	}
	a.controls[id] = item
	return item
}

func (a *summaryAccumulator) resource(resourceID string) *resourceAccumulator {
	resourceID = normalizedSummaryLabel(resourceID)
	if existing := a.resources[resourceID]; existing != nil {
		return existing
	}
	item := &resourceAccumulator{resourceID: resourceID}
	a.resources[resourceID] = item
	return item
}

func (b *bucketAccumulator) add(change ControlChange) {
	b.count++
	severity := normalizedSummaryLabel(change.Severity)
	b.severities[severity]++
	controlID := normalizedSummaryLabel(change.ControlID)
	control := b.controls[controlID]
	if control == nil {
		control = &controlCounterAccumulator{
			controlID:   controlID,
			controlName: change.ControlName,
			severity:    change.Severity,
		}
		b.controls[controlID] = control
	}
	control.count++
	resourceID := normalizedSummaryLabel(change.ResourceID)
	b.resources[resourceID]++
}

func (b *BucketSummary) increment(bucket string) {
	switch bucket {
	case "new":
		b.New++
	case "resolved":
		b.Resolved++
	case "unchanged":
		b.Unchanged++
	case "incomparable":
		b.Incomparable++
	}
}

func (a *summaryAccumulator) bucketSummaries() map[string]Bucket {
	out := map[string]Bucket{}
	for _, name := range []string{"new", "resolved", "unchanged", "incomparable"} {
		acc := a.buckets[name]
		if acc == nil {
			out[name] = Bucket{}
			continue
		}
		out[name] = Bucket{
			Count:      acc.count,
			Severities: severityCounters(acc.severities),
			Controls:   controlCounters(acc.controls),
			Resources:  resourceCounters(acc.resources),
		}
	}
	return out
}

func (a *summaryAccumulator) severitySummaries() []SeveritySummary {
	keys := make([]string, 0, len(a.severities))
	for key := range a.severities {
		keys = append(keys, key)
	}
	sortSeverityLabels(keys)
	out := make([]SeveritySummary, 0, len(keys))
	for _, key := range keys {
		item := a.severities[key]
		out = append(out, SeveritySummary{Severity: item.severity, Buckets: item.buckets})
	}
	return out
}

func (a *summaryAccumulator) controlSummaries() []ControlSummary {
	keys := make([]string, 0, len(a.controls))
	for key := range a.controls {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]ControlSummary, 0, len(keys))
	for _, key := range keys {
		item := a.controls[key]
		out = append(out, ControlSummary{
			ControlID:   item.controlID,
			ControlName: item.controlName,
			Severity:    item.severity,
			Buckets:     item.buckets,
		})
	}
	return out
}

func (a *summaryAccumulator) resourceSummaries() []ResourceSummary {
	keys := make([]string, 0, len(a.resources))
	for key := range a.resources {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]ResourceSummary, 0, len(keys))
	for _, key := range keys {
		item := a.resources[key]
		out = append(out, ResourceSummary{ResourceID: item.resourceID, Buckets: item.buckets})
	}
	return out
}

func (a *summaryAccumulator) topRegressionControls() []ControlCounter {
	regressions := map[string]*controlCounterAccumulator{}
	for _, bucketName := range []string{"new", "incomparable"} {
		bucket := a.buckets[bucketName]
		if bucket == nil {
			continue
		}
		for controlID, control := range bucket.controls {
			item := regressions[controlID]
			if item == nil {
				item = &controlCounterAccumulator{
					controlID:   control.controlID,
					controlName: control.controlName,
					severity:    control.severity,
				}
				regressions[controlID] = item
			}
			item.count += control.count
			if item.controlName == "" {
				item.controlName = control.controlName
			}
			if item.severity == "" {
				item.severity = control.severity
			}
		}
	}
	return rankedControlCounters(regressions)
}

func (a *summaryAccumulator) topRegressionResources() []ResourceCounter {
	regressions := map[string]int{}
	for _, bucketName := range []string{"new", "incomparable"} {
		bucket := a.buckets[bucketName]
		if bucket == nil {
			continue
		}
		for resourceID, count := range bucket.resources {
			regressions[resourceID] += count
		}
	}
	return rankedResourceCounters(regressions)
}

func severityCounters(counts map[string]int) []SeverityCounter {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sortSeverityLabels(keys)
	out := make([]SeverityCounter, 0, len(keys))
	for _, key := range keys {
		out = append(out, SeverityCounter{Severity: key, Count: counts[key]})
	}
	return out
}

func controlCounters(counts map[string]*controlCounterAccumulator) []ControlCounter {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]ControlCounter, 0, len(keys))
	for _, key := range keys {
		item := counts[key]
		out = append(out, ControlCounter{
			ControlID:   item.controlID,
			ControlName: item.controlName,
			Severity:    item.severity,
			Count:       item.count,
		})
	}
	return out
}

func resourceCounters(counts map[string]int) []ResourceCounter {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]ResourceCounter, 0, len(keys))
	for _, key := range keys {
		out = append(out, ResourceCounter{ResourceID: key, Count: counts[key]})
	}
	return out
}

func rankedControlCounters(counts map[string]*controlCounterAccumulator) []ControlCounter {
	out := controlCounters(counts)
	sort.SliceStable(out, func(i, j int) bool {
		left, right := out[i], out[j]
		if left.Count != right.Count {
			return left.Count > right.Count
		}
		if leftRank, rightRank := severityRank(left.Severity), severityRank(right.Severity); leftRank != rightRank {
			return leftRank > rightRank
		}
		if left.ControlID != right.ControlID {
			return left.ControlID < right.ControlID
		}
		return left.ControlName < right.ControlName
	})
	return out
}

func rankedResourceCounters(counts map[string]int) []ResourceCounter {
	out := resourceCounters(counts)
	sort.SliceStable(out, func(i, j int) bool {
		left, right := out[i], out[j]
		if left.Count != right.Count {
			return left.Count > right.Count
		}
		return left.ResourceID < right.ResourceID
	})
	return out
}

func sortSeverityLabels(values []string) {
	sort.SliceStable(values, func(i, j int) bool {
		left, right := severityRank(values[i]), severityRank(values[j])
		if left != right {
			return left > right
		}
		return values[i] < values[j]
	})
}

func normalizedSummaryLabel(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	return value
}

func thresholdLabel(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "all"
	}
	return value
}

func (c *controlAccumulator) ControlName() string {
	return strings.TrimSpace(c.controlName)
}
