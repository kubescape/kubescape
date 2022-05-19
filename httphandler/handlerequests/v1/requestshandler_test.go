package v1

// ============================================== STATUS ========================================================
// Status API
// func TestStatus(t *testing.T) {

// 	{
// 		httpHandler := NewHTTPHandler()

// 		u := url.URL{
// 			Scheme:   "http",
// 			Host:     "bla",
// 			Path:     "bla",
// 			RawQuery: "wait=true&keep=true",
// 		}
// 		request, err := http.NewRequest(http.MethodPost, u.String(), nil)
// 		httpHandler.Status(nil, request)

// 		assert.NoError(t, err)

// 		scanID := "ccccccc"

// 		req, err := getScanParamsFromRequest(request, scanID)
// 		assert.NoError(t, err)
// 		assert.Equal(t, scanID, req.scanID)
// 		assert.True(t, req.scanQueryParams.KeepResults)
// 		assert.True(t, req.scanQueryParams.ReturnResults)
// 		assert.True(t, *req.scanRequest.HostScanner)
// 		assert.True(t, *req.scanRequest.Submit)
// 		assert.Equal(t, "aaaaaaaaaa", req.scanRequest.Account)
// 	}
// }
