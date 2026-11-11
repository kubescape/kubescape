package getter

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"github.com/kubescape/regolibrary/v2/gitregostore"
)

// =======================================================================================================================
// ======================================== DownloadReleasedPolicy =======================================================
// =======================================================================================================================
var (
	_ IPolicyGetter         = &DownloadReleasedPolicy{}
	_ IExceptionsGetter     = &DownloadReleasedPolicy{}
	_ IAttackTracksGetter   = &DownloadReleasedPolicy{}
	_ IControlsInputsGetter = &DownloadReleasedPolicy{}
)

// Use gitregostore to get policies from github release
//
// A DownloadReleasedPolicy may be shared by scans that run one after another or
// at the same time. The release is downloaded into a store of its own, which
// replaces the one the getters read only once the whole release has arrived, so
// a reader sees all of the release or none of it, never the part that has
// arrived so far. At most one download is in progress at a time, and the scans
// that need the release meanwhile wait for it.
type DownloadReleasedPolicy struct {
	version string

	// mu guards gs and loading. It is never held while a download runs.
	mu sync.RWMutex
	// gs is the store every read goes to. It is empty until a download has
	// completed and is never written to after that: a download fills another
	// store and swaps it in.
	gs *gitregostore.GitRegoStore
	// loading is the download in progress, if any.
	loading *releaseLoad
}

// releaseLoad is one download of the release, which every scan that needs the
// release while it runs waits for.
type releaseLoad struct {
	done chan struct{}
	// err is the outcome. It is set before done is closed.
	err error
}

// store returns the store to read from. A caller makes one call per operation
// and reads everything from what it got, so that an operation never mixes two
// stores.
func (drp *DownloadReleasedPolicy) store() *gitregostore.GitRegoStore {
	drp.mu.RLock()
	defer drp.mu.RUnlock()
	return drp.gs
}

func NewDownloadReleasedPolicy() *DownloadReleasedPolicy {
	return &DownloadReleasedPolicy{
		gs: gitregostore.NewGitRegoStoreV2(-1),
	}
}

// NewDownloadReleasedPolicyWithVersion returns a DownloadReleasedPolicy pinned
// to a specific regolibrary release tag (e.g. "v2.0.301"). An empty version
// falls back to the latest release, matching NewDownloadReleasedPolicy.
func NewDownloadReleasedPolicyWithVersion(version string) *DownloadReleasedPolicy {
	if version == "" {
		return NewDownloadReleasedPolicy()
	}
	return &DownloadReleasedPolicy{
		gs:      gitregostore.NewGitRegoStore("https://github.com", "kubescape", "regolibrary", "releases", "download/"+version, "", -1),
		version: version,
	}
}

// IsVersionPinned reports whether this getter targets a specific, user-selected
// regolibrary release tag rather than the latest release.
func (drp *DownloadReleasedPolicy) IsVersionPinned() bool {
	if drp == nil {
		return false
	}
	return drp.version != ""
}

// CacheSource identifies the release this getter reads: the pinned tag, or
// the latest release when none is pinned.
func (drp *DownloadReleasedPolicy) CacheSource() string {
	if drp == nil {
		return CacheSourceOf(nil)
	}
	return fmt.Sprintf("release:%q", drp.version)
}

// ShouldPersistPolicyArtifacts reports whether policies fetched by this getter
// may be published to Kubescape's shared, unversioned disk fallback. A pinned
// release must not replace that fallback because the flat cache path does not
// record release provenance; doing so would let a later unpinned fallback
// silently evaluate the pinned release.
func (drp *DownloadReleasedPolicy) ShouldPersistPolicyArtifacts() bool {
	if drp == nil {
		return false
	}
	return !drp.IsVersionPinned()
}

// SetRegoObjectsWithFallback downloads the policy objects and reports whether
// the caller should fall back to the bundled cache on failure.
//
// When a version is pinned, a download failure is a hard error (fallback=false,
// err!=nil): the user explicitly asked for a specific release, so silently
// serving a different, cached policy set would be misleading. When no version
// is pinned, a download failure is not an error but requests a fallback
// (fallback=true, err=nil), preserving the existing latest-release behavior.
func (drp *DownloadReleasedPolicy) SetRegoObjectsWithFallback() (fallback bool, err error) {
	return drp.SetRegoObjectsWithFallbackContext(context.Background())
}

// SetRegoObjectsWithFallbackContext is SetRegoObjectsWithFallback for a caller
// that can be stopped while it waits for the download. A stopped caller gets the
// context's error and no request to fall back: a scan that was cancelled is not
// one that should carry on with the cache.
func (drp *DownloadReleasedPolicy) SetRegoObjectsWithFallbackContext(ctx context.Context) (fallback bool, err error) {
	if err := drp.SetRegoObjectsContext(ctx); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return false, err
		}
		if drp.version != "" {
			return false, err
		}
		if errors.Is(err, gitregostore.ErrChecksumVerification) {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// GetControl returns a control by its control ID or, when it carries one, its
// framework section number; see controlMatcher. The released store only
// indexes control IDs, so a section number is resolved from the full control
// list, and only after the control ID lookup reported the control as not
// found. A failure to read the catalog is returned as is, never as an
// unknown control.
func (drp *DownloadReleasedPolicy) GetControl(ID string) (*reporthandling.Control, error) {
	id := strings.TrimSpace(ID)
	if id == "" {
		return nil, ErrIDRequired
	}

	gs := drp.store()
	control, err := gs.GetOPAControlByID(id)
	if err == nil {
		return control, nil
	}
	notFound := err
	if err.Error() != fmt.Sprintf("control '%s' not found", id) {
		return nil, err
	}

	controls, err := gs.GetOPAControls()
	if err != nil {
		return nil, err
	}
	matcher := newControlMatcher(id)
	for i := range controls {
		matcher.offer(&controls[i])
	}
	control, err = matcher.bySection()
	if err != nil {
		return nil, err
	}
	if control == nil {
		return nil, &controlNotFoundError{cause: notFound}
	}
	return control, nil
}

func (drp *DownloadReleasedPolicy) GetFramework(name string) (*reporthandling.Framework, error) {
	gs := drp.store()
	framework, err := gs.GetOPAFrameworkByName(name)
	if err != nil {
		return nil, err
	}
	if framework != nil && strings.EqualFold(framework.Name, "allcontrols") {
		controls, err := gs.GetOPAControls()
		if err != nil {
			return nil, err
		}
		framework.Controls = controls
	}
	return framework, nil
}

func (drp *DownloadReleasedPolicy) GetFrameworks() ([]reporthandling.Framework, error) {
	gs := drp.store()
	frameworks, err := gs.GetOPAFrameworks()
	if err != nil {
		return nil, err
	}
	for i := range frameworks {
		if strings.EqualFold(frameworks[i].Name, "allcontrols") {
			controls, err := gs.GetOPAControls()
			if err != nil {
				return nil, err
			}
			frameworks[i].Controls = controls
		}
	}
	return frameworks, nil
}

func (drp *DownloadReleasedPolicy) ListFrameworks() ([]string, error) {
	return drp.store().GetOPAFrameworksNamesList()
}

func (drp *DownloadReleasedPolicy) ListControls() ([]string, error) {
	gs := drp.store()
	controlsIDsList, err := gs.GetOPAControlsIDsList()
	if err != nil {
		return []string{}, err
	}
	controlsNamesList, err := gs.GetOPAControlsNamesList()
	if err != nil {
		return []string{}, err
	}
	controls, err := gs.GetOPAControls()
	if err != nil {
		return []string{}, err
	}
	var controlsFrameworksList [][]string
	for _, control := range controls {
		controlsFrameworksList = append(controlsFrameworksList, gs.GetOpaFrameworkListByControlID(control.ControlID))
	}
	controlsNamesWithIDsandFrameworksList := make([]string, len(controlsIDsList))
	// by design all slices have the same length
	for i := range controlsIDsList {
		controlsNamesWithIDsandFrameworksList[i] = fmt.Sprintf("%v|%v|%v", controlsIDsList[i], controlsNamesList[i], strings.Join(controlsFrameworksList[i], ", "))
	}
	return controlsNamesWithIDsandFrameworksList, nil
}

func (drp *DownloadReleasedPolicy) GetControlsInputs(ctx context.Context, clusterName string) (map[string][]string, error) {
	defaultConfigInputs, err := drp.store().GetDefaultConfigInputs()
	if err != nil {
		return nil, err
	}
	if defaultConfigInputs.Settings.PostureControlInputs == nil {
		// the rego store failed to load, so no control inputs are available;
		// report it as an error instead of silently returning empty inputs
		return nil, fmt.Errorf("no control configuration inputs available")
	}
	return defaultConfigInputs.Settings.PostureControlInputs, err
}

func (drp *DownloadReleasedPolicy) GetAttackTracks() ([]v1alpha1.AttackTrack, error) {
	attackTracks, err := drp.store().GetAttackTracks()
	if err != nil {
		return nil, err
	}
	return attackTracks, err
}

func (drp *DownloadReleasedPolicy) SetRegoObjects() error {
	return drp.SetRegoObjectsContext(context.Background())
}

// SetRegoObjectsContext makes sure the release is loaded, downloading it when it
// is not. The download is shared: a caller that arrives while one is running
// waits for it and gets its outcome, and a failed one is not remembered, so the
// next caller downloads again. A caller whose ctx ends stops waiting and gets the
// context's error; the download itself is not stopped, since the files it needs
// are fetched without a context, and it ends by loading the release for the next
// caller or by failing.
func (drp *DownloadReleasedPolicy) SetRegoObjectsContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	drp.mu.Lock()
	if loaded(drp.gs) {
		drp.mu.Unlock()
		return nil
	}
	load := drp.loading
	if load == nil {
		load = &releaseLoad{done: make(chan struct{})}
		drp.loading = load
		go drp.download(load, drp.gs)
	}
	drp.mu.Unlock()

	select {
	case <-load.done:
		return load.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// loaded reports whether the store holds the release.
func loaded(gs *gitregostore.GitRegoStore) bool {
	fwNames, err := gs.GetOPAFrameworksNamesList()
	return len(fwNames) != 0 && err == nil
}

// download fetches the release into a store of its own, configured like base, and
// swaps it in for the one the getters read when, and only when, all of it has
// arrived. A download that fails leaves what the getters read as it was.
func (drp *DownloadReleasedPolicy) download(load *releaseLoad, base *gitregostore.GitRegoStore) {
	candidate := gitregostore.NewGitRegoStore(base.BaseUrl, base.Owner, base.Repository, base.Path, base.Tag, base.Branch, base.FrequencyPullFromGitMinutes)
	candidate.URL = base.URL

	err := candidate.SetRegoObjects()
	if err != nil && drp.version != "" {
		err = fmt.Errorf("failed to download controls for pinned version %q: %w", drp.version, err)
	}

	drp.mu.Lock()
	if err == nil {
		drp.gs = candidate
	}
	drp.loading = nil
	drp.mu.Unlock()

	load.err = err
	close(load.done)
}

func (drp *DownloadReleasedPolicy) GetExceptions(ctx context.Context, clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
	exceptions, err := drp.store().GetSystemPostureExceptionPolicies()
	if err != nil {
		return nil, err
	}
	return exceptions, nil
}
