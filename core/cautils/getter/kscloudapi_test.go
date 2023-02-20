package getter

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// Kubescape API routes

	pathAttackTracks    = "/api/v1/attackTracks"
	pathFrameworks      = "/api/v1/armoFrameworks"
	pathExceptions      = "/api/v1/armoPostureExceptions"
	pathTenant          = "/api/v1/createTenant"
	pathExceptionPolicy = "/api/v1/postureExceptionPolicy"
	pathCustomerConfig  = "/api/v1/armoCustomerConfiguration"
	pathLogin           = "/identity/resources/auth/v1/api-token"
	pathToken           = "/api/v1/openid_customers" //nolint:gosec

	// extra mock API routes

	pathTestPost   = "/test-post"
	pathTestDelete = "/test-delete"
	pathTestGet    = "/test-get"
)

func TestKSCloudAPI(t *testing.T) {
	// NOTE: mock handlers do not use "require" in order to let goroutines end normally upon failure.

	srv := mockAPIServer(t)
	t.Cleanup(srv.Close)

	ks := NewKSCloudAPICustomized(
		"",         // ERURL: report URL (not used)
		srv.Root(), // BRURL: API URL
		"",         // FEURL: UI URL (not used)
		srv.Root(), // AUTHURL: Authentication URL
	)
	ks.SetAccountID("armo")
	ks.SetClientID("armo")
	ks.SetSecretKey("armo")

	t.Run("with generic REST methods", func(t *testing.T) {
		hdrs := map[string]string{"key": "value"}
		body := []byte("body-post")

		t.Run("should POST", func(t *testing.T) {
			t.Parallel()

			resp, err := ks.Post(srv.URL(pathTestPost), hdrs, body)
			require.NoError(t, err)

			require.EqualValues(t, string(body), resp)
		})

		t.Run("should POST (no headers)", func(t *testing.T) {
			t.Parallel()

			resp, err := ks.Post(srv.URL(pathTestPost), nil, body)
			require.NoError(t, err)

			require.EqualValues(t, string(body), resp)
		})

		t.Run("should DELETE", func(t *testing.T) {
			t.Parallel()

			resp, err := ks.Delete(srv.URL(pathTestDelete), hdrs)
			require.NoError(t, err)

			require.EqualValues(t, "body-delete", resp)
		})

		t.Run("should GET", func(t *testing.T) {
			t.Parallel()

			resp, err := ks.Get(srv.URL(pathTestGet), hdrs)
			require.NoError(t, err)

			require.EqualValues(t, "body-get", resp)
		})
	})

	t.Run("should retrieve AttackTracks", func(t *testing.T) {
		t.Parallel()

		tracks, err := ks.GetAttackTracks()
		require.NoError(t, err)
		require.NotNil(t, tracks)

		expected := mockAttackTracks()

		// make sure controls don't leak
		for i := range expected {
			expected[i].Spec.Data.Controls = nil // doesn't pass the JSON marshal
			for j := range expected[i].Spec.Data.SubSteps {
				expected[i].Spec.Data.SubSteps[j].Controls = nil
			}
		}
		require.EqualValues(t, expected, tracks)
	})

	t.Run("with frameworks", func(t *testing.T) {
		t.Run("should retrieve Framework #1", func(t *testing.T) {
			t.Parallel()

			framework, err := ks.GetFramework("mock-1")
			require.NoError(t, err)
			require.NotNil(t, framework)

			mocked := mockFrameworks()
			expected := &mocked[0]
			require.EqualValues(t, expected, framework)
		})

		t.Run("should retrieve Framework #2", func(t *testing.T) {
			t.Parallel()

			framework, err := ks.GetFramework("mock-2")
			require.NoError(t, err)
			require.NotNil(t, framework)

			mocked := mockFrameworks()
			expected := &mocked[1]
			require.EqualValues(t, expected, framework)
		})

		t.Run("should retrieve native Framework", func(t *testing.T) {
			t.Parallel()

			const testFramework = "MITRE"
			expected, err := os.ReadFile(testFrameworkFile(testFramework))
			require.NoError(t, err)

			framework, err := ks.GetFramework("miTrE")
			require.NoError(t, err)
			require.NotNil(t, framework)
			jazon, err := json.Marshal(framework)
			require.NoError(t, err)
			require.JSONEq(t, string(expected), string(jazon))
		})

		t.Run("should retrieve all Frameworks", func(t *testing.T) {
			t.Parallel()

			// NOTE: MITRE fixture is not part of the base mock

			expected := mockFrameworks()
			frameworks, err := ks.GetFrameworks()
			require.NoError(t, err)
			require.Len(t, frameworks, 3)
			require.EqualValues(t, expected, frameworks)
		})

		t.Run("should list all Frameworks", func(t *testing.T) {
			t.Parallel()

			mocks := mockFrameworks()
			expected := make([]string, 0, 3)
			for _, fw := range mocks {
				expected = append(expected, fw.Name)
			}

			frameworkNames, err := ks.ListFrameworks()
			require.NoError(t, err)
			require.Len(t, frameworkNames, 3)
			require.ElementsMatch(t, expected, frameworkNames)
		})

		t.Run("should list custom Frameworks", func(t *testing.T) {
			t.Parallel()

			mocks := mockFrameworks()
			expected := make([]string, 0, 2)
			for _, fw := range mocks[:len(mocks)-1] {
				expected = append(expected, fw.Name)
			}

			frameworkNames, err := ks.ListCustomFrameworks()
			require.NoError(t, err)
			require.Len(t, frameworkNames, 2)
			require.ElementsMatch(t, expected, frameworkNames)
		})
	})

	t.Run("with controls", func(t *testing.T) {
		t.Run("should NOT retrieve Control (not a public API)", func(t *testing.T) {
			t.Parallel()

			const id = "control-1"

			control, err := ks.GetControl(id)
			require.Error(t, err)
			require.Nil(t, control)
			require.Contains(t, err.Error(), "is not public")
		})

		t.Run("should NOT list Controls (not a public API)", func(t *testing.T) {
			t.Parallel()

			control, err := ks.ListControls()
			require.Error(t, err)
			require.Nil(t, control)
			require.Contains(t, err.Error(), "is not public")
		})
	})

	t.Run("with exceptions", func(t *testing.T) {
		t.Run("should retrieve Exceptions", func(t *testing.T) {
			t.Parallel()

			expected := mockExceptions()
			exceptions, err := ks.GetExceptions("")
			require.NoError(t, err)
			require.Len(t, exceptions, 2)
			require.EqualValues(t, expected, exceptions)
		})

		t.Run("should POST Exceptions", func(t *testing.T) {
			t.Parallel()

			require.NoError(t,
				ks.PostExceptions(mockExceptions()),
			)
		})

		t.Run("DELETE Exception requires a name", func(t *testing.T) {
			t.Parallel()

			require.Error(t,
				ks.DeleteException(""),
			)
		})

		t.Run("should DELETE Exception", func(t *testing.T) {
			t.Parallel()

			require.NoError(t,
				ks.DeleteException("mock"),
			)
		})
	})

	t.Run("should retrieve Tenant", func(t *testing.T) {
		t.Parallel()

		expected := mockTenantResponse()
		tenant, err := ks.GetTenant()
		require.NoError(t, err)
		require.NotNil(t, tenant)
		require.EqualValues(t, expected, tenant)
	})

	t.Run("with CustomerConfig", func(t *testing.T) {
		t.Run("empty CustomerConfig", func(t *testing.T) {
			t.Parallel()

			kno := NewKSCloudAPICustomized(
				"",
				srv.Root(),
				"",
				"",
			)

			account, err := kno.GetAccountConfig("")
			require.NoError(t, err)
			require.NotNil(t, account)
			require.Empty(t, *account)
		})

		t.Run("should retrieve CustomerConfig", func(t *testing.T) {
			t.Parallel()

			expected := mockCustomerConfig("", "")()
			account, err := ks.GetAccountConfig("")
			require.NoError(t, err)
			require.NotNil(t, account)
			require.EqualValues(t, expected, account)
		})

		t.Run("should retrieve CustomerConfig for cluster", func(t *testing.T) {
			t.Parallel()

			const cluster = "special-cluster"

			expected := mockCustomerConfig(cluster, "")()
			account, err := ks.GetAccountConfig(cluster)
			require.NoError(t, err)
			require.NotNil(t, account)
			require.EqualValues(t, expected, account)
		})

		t.Run("should retrieve scoped CustomerConfig", func(t *testing.T) {
			// NOTE: this is not directly exposed as an exported method of the API client,
			// but called internally on some specific condition that is hard to reproduce in test.
			t.Parallel()

			mocks := mockCustomerConfig("", "customer")()
			expected, err := json.Marshal(mocks)
			require.NoError(t, err)

			account, err := ks.Get(ks.getAccountConfigDefault(""), nil)
			require.NoError(t, err)
			require.NotNil(t, account)
			require.JSONEq(t, string(expected), account)
		})

		t.Run("should retrieve ControlInputs", func(t *testing.T) {
			t.Parallel()

			config := mockCustomerConfig("", "")()
			expected := config.Settings.PostureControlInputs

			inputs, err := ks.GetControlsInputs("")
			require.NoError(t, err)
			require.NotNil(t, inputs)
			require.EqualValues(t, expected, inputs)
		})
	})

	t.Run("with login", func(t *testing.T) {
		t.Run("login requires an account ID", func(t *testing.T) {
			t.Parallel()

			kno := NewKSCloudAPICustomized(
				"",
				srv.Root(),
				"",
				"",
			)
			kno.SetClientID("armo")
			kno.SetSecretKey("armo")

			err := kno.Login()
			require.Error(t, err)
			require.Contains(t, err.Error(), "missing accountID")
		})

		t.Run("login requires a client ID", func(t *testing.T) {
			t.Parallel()

			kno := NewKSCloudAPICustomized(
				"",
				srv.Root(),
				"",
				"",
			)
			kno.SetAccountID("armo")
			kno.SetSecretKey("armo")

			err := kno.Login()
			require.Error(t, err)
			require.Contains(t, err.Error(), "missing clientID")
		})

		t.Run("login requires a secret key", func(t *testing.T) {
			t.Parallel()

			kno := NewKSCloudAPICustomized(
				"",
				srv.Root(),
				"",
				"",
			)
			kno.SetAccountID("armo")
			kno.SetClientID("armo")

			err := kno.Login()
			require.Error(t, err)
			require.Contains(t, err.Error(), "missing secretKey")
		})

		t.Run("should login", func(t *testing.T) {
			t.Parallel()

			require.NoError(t, ks.Login())
			require.True(t, ks.IsLoggedIn())
		})
	})

	t.Run("with getters & setters", func(t *testing.T) {
		t.Parallel()

		kno := NewKSCloudAPICustomized(
			"",
			srv.Root(),
			"",
			"",
		)

		pickString := func() string {
			return strconv.Itoa(rand.Intn(10000)) //nolint:gosec
		}

		t.Run("should get&set account", func(t *testing.T) {
			str := pickString()
			kno.SetAccountID(str)
			require.Equal(t, str, kno.GetAccountID())
		})

		t.Run("should get&set client", func(t *testing.T) {
			str := pickString()
			kno.SetClientID(str)
			require.Equal(t, str, kno.GetClientID())
		})

		t.Run("should get&set key", func(t *testing.T) {
			str := pickString()
			kno.SetSecretKey(str)
			require.Equal(t, str, kno.GetSecretKey())
		})

		t.Run("should get&set report URL", func(t *testing.T) {
			str := pickString()
			kno.SetCloudReportURL(str)
			require.Equal(t, str, kno.GetCloudReportURL())
		})

		t.Run("should get&set API URL", func(t *testing.T) {
			str := pickString()
			kno.SetCloudAPIURL(str)
			require.Equal(t, str, kno.GetCloudAPIURL())
		})

		t.Run("should get&set UI URL", func(t *testing.T) {
			str := pickString()
			kno.SetCloudUIURL(str)
			require.Equal(t, str, kno.GetCloudUIURL())
		})

		t.Run("should get&set auth URL", func(t *testing.T) {
			str := pickString()
			kno.SetCloudAuthURL(str)
			require.Equal(t, str, kno.GetCloudAuthURL())
		})
	})

	t.Run("with API errors", func(t *testing.T) {
		// exercise the client when the API returns errors
		t.Parallel()

		errAPI := errors.New("test error")
		errSrv := mockAPIServer(t, withAPIError(errAPI))
		t.Cleanup(errSrv.Close)

		ke := NewKSCloudAPICustomized(
			"",
			errSrv.Root(),
			"",
			errSrv.Root(),
		)
		ke.SetAccountID("armo")
		ke.SetClientID("armo")
		ke.SetSecretKey("armo")

		hdrs := map[string]string{"key": "value"}
		body := []byte("body-post")

		t.Run("API calls should error", func(t *testing.T) {
			_, err := ke.Post(errSrv.URL(pathTestPost), hdrs, body)
			require.Error(t, err)
			require.Contains(t, err.Error(), errAPI.Error())

			_, err = ke.Delete(errSrv.URL(pathTestDelete), hdrs)
			require.Error(t, err)
			require.Contains(t, err.Error(), errAPI.Error())

			_, err = ke.Get(errSrv.URL(pathTestGet), hdrs)
			require.Error(t, err)
			require.Contains(t, err.Error(), errAPI.Error())

			_, err = ke.GetExceptions("")
			require.Error(t, err)
			require.Contains(t, err.Error(), errAPI.Error())

			err = ke.PostExceptions(mockExceptions())
			require.Error(t, err)
			require.Contains(t, err.Error(), errAPI.Error())

			err = ke.DeleteException("mock")
			require.Error(t, err)
			require.Contains(t, err.Error(), errAPI.Error())

			_, err = ke.GetTenant()
			require.Error(t, err)
			require.Contains(t, err.Error(), errAPI.Error())

			_, err = ke.GetControlsInputs("")
			require.Error(t, err)
			require.Contains(t, err.Error(), errAPI.Error())

			_, err = ke.GetAccountConfig("")
			require.Error(t, err)
			require.Contains(t, err.Error(), errAPI.Error())

			err = ke.Login()
			require.Error(t, err)
			require.Contains(t, err.Error(), "error authenticating")
			require.False(t, ke.IsLoggedIn())
		})

		t.Run("API calls should return nil, but no error", func(t *testing.T) {
			// NOTE(fredbi): IMHO this is a bad idea to mute errors
			// and leave the possibility to return (nil, nil) to the caller.
			//
			// We should bubble up the error and be consistent with other methods.

			tracks, err := ke.GetAttackTracks()
			require.NoError(t, err)
			require.Nil(t, tracks)

			fw, err := ke.GetFramework("mock-1")
			require.NoError(t, err)
			require.Nil(t, fw)

			fws, err := ke.GetFrameworks()
			require.NoError(t, err)
			require.Nil(t, fws)

			_, err = ke.ListFrameworks()
			require.Error(t, err)
			require.Contains(t, err.Error(), errAPI.Error())

			_, err = ke.ListCustomFrameworks()
			require.Error(t, err)
			require.Contains(t, err.Error(), errAPI.Error())
		})
	})

	t.Run("with API returning invalid response", func(t *testing.T) {
		// exercise the client when the API returns an invalid response
		t.Parallel()

		errSrv := mockAPIServer(t, withAPIGarbled(true))
		t.Cleanup(errSrv.Close)

		ke := NewKSCloudAPICustomized(
			"",
			errSrv.Root(),
			"",
			errSrv.Root(),
		)
		ke.SetAccountID("armo")
		ke.SetClientID("armo")
		ke.SetSecretKey("armo")

		t.Run("API calls should return unmarshalling error", func(t *testing.T) {
			// only API calls that return a typed response are checked

			_, err := ke.GetExceptions("")
			require.Error(t, err)

			_, err = ke.GetTenant()
			require.Error(t, err)

			_, err = ke.GetAccountConfig("")
			require.Error(t, err)

			err = ke.Login()
			require.Error(t, err)
			require.False(t, ke.IsLoggedIn())

			_, err = ke.GetControlsInputs("")
			require.Error(t, err)

			_, err = ke.GetAttackTracks()
			require.Error(t, err)

			_, err = ke.GetFramework("mock-1")
			require.Error(t, err)

			_, err = ke.GetFrameworks()
			require.Error(t, err)

			_, err = ke.ListFrameworks()
			require.Error(t, err)

			_, err = ke.ListCustomFrameworks()
			require.Error(t, err)
		})
	})

}

func TestKSCloudAPISmoke(t *testing.T) {
	t.Run("smoke-test constructors", func(t *testing.T) {
		require.NotNil(t, NewKSCloudAPIDev())
		require.NotNil(t, NewKSCloudAPIStaging())
		require.NotNil(t, NewKSCloudAPIProd())
	})
}

type (
	testServer struct {
		*httptest.Server
		*mockAPIOptions
	}

	mockAPIOption  func(*mockAPIOptions)
	mockAPIOptions struct {
		withError   error // responds error systematically
		withGarbled bool  // responds garbled JSON (if a JSON response is expected)
	}
)

func (s *testServer) Root() string {
	return s.Server.URL
}

func (s *testServer) URL(pth string) string {
	pth = strings.TrimLeft(pth, "/")

	return fmt.Sprintf("%s/%s", s.Server.URL, pth)
}

// WantsError responds with the configured error.
func (o *mockAPIOptions) WantsError(w http.ResponseWriter) bool {
	if o.withError == nil {
		return false
	}

	http.Error(w, o.withError.Error(), http.StatusInternalServerError)

	return true
}

// WantsGarbled responds with invalid JSON
func (o *mockAPIOptions) WantsGarbled(w http.ResponseWriter) bool {
	if !o.withGarbled {
		return false
	}

	invalidJSON(w)

	return true
}

func withAPIError(err error) mockAPIOption {
	return func(o *mockAPIOptions) {
		o.withError = err
	}
}

func withAPIGarbled(enabled bool) mockAPIOption {
	return func(o *mockAPIOptions) {
		o.withGarbled = enabled
	}
}

func apiOptions(opts []mockAPIOption) *mockAPIOptions {
	o := &mockAPIOptions{}
	for _, apply := range opts {
		apply(o)
	}

	return o
}

func mockAPIServer(t testing.TB, opts ...mockAPIOption) *testServer {
	h := http.NewServeMux()

	// test options: regular mock (default), error or garbled JSON output
	server := &testServer{
		Server:         httptest.NewServer(h),
		mockAPIOptions: apiOptions(opts),
	}

	h.HandleFunc(pathTestPost, func(w http.ResponseWriter, r *http.Request) {
		if !isPost(t, r) {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		if server.WantsError(w) {
			return
		}

		if server.WantsGarbled(w) {
			return
		}

		echoRequest(w, r)
	})

	h.HandleFunc(pathTestDelete, func(w http.ResponseWriter, r *http.Request) {
		if !isDelete(t, r) {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		if server.WantsError(w) {
			return
		}

		if server.WantsGarbled(w) {
			return
		}

		echoHeaders(w, r)
		fmt.Fprintf(w, "body-delete")
	})

	h.HandleFunc(pathTestGet, func(w http.ResponseWriter, r *http.Request) {
		if !isGet(t, r) {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		if server.WantsError(w) {
			return
		}

		if server.WantsGarbled(w) {
			return
		}

		echoHeaders(w, r)
		fmt.Fprintf(w, "body-get")
	})

	h.HandleFunc(pathAttackTracks, mockHandlerAttackTracks(t, opts...))
	h.HandleFunc(pathFrameworks, mockHandlerFrameworks(t, opts...))
	h.HandleFunc(pathExceptions, mockHandlerExceptions(t, opts...))
	h.HandleFunc(pathTenant, mockHandlerTenant(t, opts...))
	h.HandleFunc(pathExceptionPolicy, mockHandlerPostureExceptionPolicy(t, opts...))
	h.HandleFunc(pathCustomerConfig, mockHandlerCustomerConfiguration(t, opts...))
	h.HandleFunc(pathLogin, mockHandlerLogin(t, opts...))
	h.HandleFunc(pathToken, mockHandlerToken(t, opts...))

	return server
}

func mockHandlerGetWithGUID[T any](t testing.TB, generator func() T, opts ...mockAPIOption) func(http.ResponseWriter, *http.Request) {
	o := apiOptions(opts)

	return func(w http.ResponseWriter, r *http.Request) {
		if !isGet(t, r) {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		if !hasGUID(t, r) {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if o.WantsError(w) {
			return
		}

		if o.WantsGarbled(w) {
			return
		}

		enc := json.NewEncoder(w)
		var doc T
		assert.NoErrorf(t, enc.Encode(generator()), "expected %T fixture to marshal to JSON", doc)
	}
}

func mockHandlerFrameworks(t testing.TB, opts ...mockAPIOption) func(http.ResponseWriter, *http.Request) {
	o := apiOptions(opts)

	return func(w http.ResponseWriter, r *http.Request) {
		if !isGet(t, r) {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		if !hasGUID(t, r) {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if o.WantsError(w) {
			return
		}

		if o.WantsGarbled(w) {
			return
		}

		frameworks := mockFrameworks()
		name := r.Form.Get("frameworkName")
		if name == "" {
			enc := json.NewEncoder(w)
			assert.NoErrorf(t, enc.Encode(frameworks), "expected Framework fixture to marshal to JSON")

			return
		}

		assert.Contains(t, []string{"mock-1", "mock-2", "MITRE"}, name)

		var framework reporthandling.Framework
		switch name {
		case "mock-1":
			framework = frameworks[0]
		case "mock-2":
			framework = frameworks[1]
		case "MITRE":
			// load MITRE from JSON fixture
			const testFramework = "MITRE"
			buf, err := os.ReadFile(testFrameworkFile(testFramework))
			if !assert.NoError(t, err) {
				w.WriteHeader(http.StatusInternalServerError)

				return
			}
			_, _ = w.Write(buf)
		}

		enc := json.NewEncoder(w)
		assert.NoErrorf(t, enc.Encode(framework), "expected Framework fixture to marshal to JSON")
	}
}

func mockHandlerAttackTracks(t testing.TB, opts ...mockAPIOption) func(http.ResponseWriter, *http.Request) {
	return mockHandlerGetWithGUID(t, mockAttackTracks, opts...)
}

func mockHandlerExceptions(t testing.TB, opts ...mockAPIOption) func(http.ResponseWriter, *http.Request) {
	return mockHandlerGetWithGUID(t, mockExceptions, opts...)
}

func mockHandlerTenant(t testing.TB, opts ...mockAPIOption) func(http.ResponseWriter, *http.Request) {
	return mockHandlerGetWithGUID(t, mockTenantResponse, opts...)
}

func mockHandlerCustomerConfiguration(t testing.TB, opts ...mockAPIOption) func(http.ResponseWriter, *http.Request) {
	o := apiOptions(opts)

	return func(w http.ResponseWriter, r *http.Request) {
		if !assert.NoErrorf(t, r.ParseForm(), "expected params to parse") {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if o.WantsError(w) {
			return
		}

		if o.WantsGarbled(w) {
			return
		}

		cluster := r.Form.Get("clusterName")
		scope := r.Form.Get("scope")

		mockHandlerGetWithGUID(t, mockCustomerConfig(cluster, scope), opts...)(w, r)
	}
}

func mockHandlerPostureExceptionPolicy(t testing.TB, opts ...mockAPIOption) func(http.ResponseWriter, *http.Request) {
	o := apiOptions(opts)

	return func(w http.ResponseWriter, r *http.Request) {
		assert.Containsf(t, []string{http.MethodPost, http.MethodDelete}, r.Method, "expected a POST or DELETE method, but got %q", r.Method)
		if !assert.NoErrorf(t, r.ParseForm(), "expected params to parse") {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if !assert.NotEmpty(t, r.Form) {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if o.WantsError(w) {
			return
		}

		if o.WantsGarbled(w) {
			return
		}

		if r.Method == http.MethodPost {
			if !isJSON(t, r) {
				w.WriteHeader(http.StatusBadRequest)

				return
			}

			buf, err := io.ReadAll(r.Body)
			defer func() {
				_ = r.Body.Close()
			}()

			if !assert.NoError(t, err) {
				w.WriteHeader(http.StatusInternalServerError)

				return
			}

			var payload armotypes.PostureExceptionPolicy
			if !assert.NoErrorf(t, json.Unmarshal(buf, &payload), "expected payload to unmarshal into PostureExceptionPolicy, but got: %q", string(buf)) {
				w.WriteHeader(http.StatusBadRequest)
			}

			return
		}

		// DELETE

		if !hasGUID(t, r) {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if name := r.Form.Get("policyName"); name == "" {
			w.WriteHeader(http.StatusBadRequest)
		}
	}
}

func mockHandlerLogin(t testing.TB, opts ...mockAPIOption) func(http.ResponseWriter, *http.Request) {
	o := apiOptions(opts)

	return func(w http.ResponseWriter, r *http.Request) {
		if !isPost(t, r) {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		if !isJSON(t, r) {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if o.WantsError(w) {
			return
		}

		if o.WantsGarbled(w) {
			return
		}

		w.Header().Add("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		assert.NoErrorf(t, enc.Encode(mockLoginResponse()), "expected %T fixture to marshal to JSON", FeLoginResponse{})
	}
}

func mockHandlerToken(t testing.TB, opts ...mockAPIOption) func(http.ResponseWriter, *http.Request) {
	o := apiOptions(opts)

	return func(w http.ResponseWriter, r *http.Request) {
		if !isPost(t, r) {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		if !isJSON(t, r) {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if o.WantsError(w) {
			return
		}

		if o.WantsGarbled(w) {
			return
		}

		buf, err := io.ReadAll(r.Body)
		defer func() {
			_ = r.Body.Close()
		}()

		if !assert.NoError(t, err) {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		var payload KSCloudSelectCustomer
		if !assert.NoErrorf(t, json.Unmarshal(buf, &payload), "expected payload to unmarshal into KSCloudSelectCustomer, but got: %q", string(buf)) {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if !assert.NotEmptyf(t, payload.SelectedCustomerGuid, "requires account GUID in payload") {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		auth := r.Header.Get("Authorization")
		if !assert.NotEmptyf(t, auth, "expected an Authorization header") {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		var token string
		_, err = fmt.Sscanf(auth, "Bearer %s", &token)
		if !assert.NoErrorf(t, err, "expected a Bearer token in the Authorization header") {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		if !assert.NotEmptyf(t, token, "bearer token is required") {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		http.SetCookie(w, &http.Cookie{Name: "auth", Value: "someToken", SameSite: http.SameSiteStrictMode})
	}
}

func echoRequest(w http.ResponseWriter, r *http.Request) {
	echoHeaders(w, r)
	echoBody(w, r)
}

func echoHeaders(w http.ResponseWriter, r *http.Request) {
	for key, vals := range r.Header {
		for _, val := range vals {
			w.Header().Add(key, val)
		}
	}
}

func echoBody(w http.ResponseWriter, r *http.Request) {
	defer func() { _ = r.Body.Close() }()
	_, _ = io.Copy(w, r.Body)
}

func isPost(t testing.TB, r *http.Request) bool {
	return assert.Truef(t, strings.EqualFold(http.MethodPost, r.Method), "expected a POST method called, but got %q", r.Method)
}

func isDelete(t testing.TB, r *http.Request) bool {
	return assert.Truef(t, strings.EqualFold(http.MethodDelete, r.Method), "expected a DELETE method called, but got %q", r.Method)
}

func isGet(t testing.TB, r *http.Request) bool {
	return assert.Truef(t, strings.EqualFold(http.MethodGet, r.Method), "expected a GET method called, but got %q", r.Method)
}

func isJSON(t testing.TB, r *http.Request) bool {
	contentType := r.Header.Get("Content-Type")

	return assert.Equalf(t, "application/json", contentType, "expected application/json content type")
}

func hasGUID(t testing.TB, r *http.Request) bool {
	if !assert.NoErrorf(t, r.ParseForm(), "expected params to parse") {
		return false
	}

	if !assert.NotEmpty(t, r.Form) {
		return false
	}

	if !assert.NotEmpty(t, r.Form.Get("customerGUID")) {
		return false
	}

	return true
}

func invalidJSON(w http.ResponseWriter) {
	fmt.Fprintf(w, `{"garbled":`)
}
