package cautils

type RootInfo struct {
	Logger       string // logger level
	LoggerName   string // logger name ("pretty"/"zap"/"none")
	CacheDir     string // cached dir
	DisableColor bool   // Disable Color

	ArmoBEURLs    string // armo url
	ArmoBEURLsDep string // armo url
}

// func (rootInfo *RootInfo) InitLogger() {
// 	logger.DisableColor(rootInfo.DisableColor)

// 	if rootInfo.LoggerName == "" {
// 		if l := os.Getenv("KS_LOGGER_NAME"); l != "" {
// 			rootInfo.LoggerName = l
// 		} else {
// 			if isatty.IsTerminal(os.Stdout.Fd()) {
// 				rootInfo.LoggerName = "pretty"
// 			} else {
// 				rootInfo.LoggerName = "zap"
// 			}
// 		}
// 	}

// 	logger.InitLogger(rootInfo.LoggerName)

// }
// func (rootInfo *RootInfo) InitLoggerLevel() error {
// 	if rootInfo.Logger == helpers.InfoLevel.String() {
// 	} else if l := os.Getenv("KS_LOGGER"); l != "" {
// 		rootInfo.Logger = l
// 	}

// 	if err := logger.L().SetLevel(rootInfo.Logger); err != nil {
// 		return fmt.Errorf("supported levels: %s", strings.Join(helpers.SupportedLevels(), "/"))
// 	}
// 	return nil
// }

// func (rootInfo *RootInfo) InitCacheDir() error {
// 	if rootInfo.CacheDir == getter.DefaultLocalStore {
// 		getter.DefaultLocalStore = rootInfo.CacheDir
// 	} else if cacheDir := os.Getenv("KS_CACHE_DIR"); cacheDir != "" {
// 		getter.DefaultLocalStore = cacheDir
// 	} else {
// 		return nil // using default cache dir location
// 	}

// 	// TODO create dir if not found exist
// 	// logger.L().Debug("cache dir updated", helpers.String("path", getter.DefaultLocalStore))
// 	return nil
// }
// func (rootInfo *RootInfo) InitEnvironment() error {

// 	urlSlices := strings.Split(rootInfo.ArmoBEURLs, ",")
// 	if len(urlSlices) != 1 && len(urlSlices) < 3 {
// 		return fmt.Errorf("expected at least 2 URLs (report,api,frontend,auth)")
// 	}
// 	switch len(urlSlices) {
// 	case 1:
// 		switch urlSlices[0] {
// 		case "dev", "development":
// 			getter.SetARMOAPIConnector(getter.NewARMOAPIDev())
// 		case "stage", "staging":
// 			getter.SetARMOAPIConnector(getter.NewARMOAPIStaging())
// 		case "":
// 			getter.SetARMOAPIConnector(getter.NewARMOAPIProd())
// 		default:
// 			return fmt.Errorf("unknown environment")
// 		}
// 	case 2:
// 		armoERURL := urlSlices[0] // mandatory
// 		armoBEURL := urlSlices[1] // mandatory
// 		getter.SetARMOAPIConnector(getter.NewARMOAPICustomized(armoERURL, armoBEURL, "", ""))
// 	case 3, 4:
// 		var armoAUTHURL string
// 		armoERURL := urlSlices[0] // mandatory
// 		armoBEURL := urlSlices[1] // mandatory
// 		armoFEURL := urlSlices[2] // mandatory
// 		if len(urlSlices) <= 4 {
// 			armoAUTHURL = urlSlices[3]
// 		}
// 		getter.SetARMOAPIConnector(getter.NewARMOAPICustomized(armoERURL, armoBEURL, armoFEURL, armoAUTHURL))
// 	}
// 	return nil
// }
