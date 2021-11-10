 package cmd

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"net/http"
	"github.com/armosec/kubescape/cautils/getter"
)

type scanDetails struct {
	frameworkControl string
	name string
	excludedNamespaces string
	useExceptions string
}

type serverDetails struct {
	port uint16
	scanInterval uint
	updateInterval uint
	scan scanDetails
}

type serverState struct {
	valid bool
	response string
	mtx sync.Mutex
}

var server serverDetails
var state serverState

// metricsCmd represents the metrics command
var metricsCmd = &cobra.Command{
	Use:   "metrics <command>",
	Short: "Metrics runs kubescape as a web server",
	Long:  `An http server will start on the given port`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 2 {
			return fmt.Errorf("requires two arguments : framework/control <framework-name>/<control-name>")
		}
		if !strings.EqualFold(args[0], "framework") && !strings.EqualFold(args[0], "control") {
			return fmt.Errorf("invalid parameter '%s'. Supported parameters: framework, control", args[0])
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		http.HandleFunc("/metrics", metrics)
		http.HandleFunc("/livez", livez)
		http.HandleFunc("/readyz", readyz)
		server.scan.frameworkControl = args[0]
		server.scan.name = args[1]

		state.valid = false
		go backgroundScanner(
			server.scan,
			time.Duration(server.scanInterval) * time.Second,
			time.Duration(server.updateInterval) * time.Second)
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", server.port), nil))
	},
}

func init() {
	rootCmd.AddCommand(metricsCmd)
	metricsCmd.PersistentFlags().Uint16VarP(&server.port, "port", "p", 80, "Port to serve http on")
	metricsCmd.PersistentFlags().UintVarP(&server.scanInterval, "interval", "i", 300, "Interval in seconds between running scans")
	metricsCmd.PersistentFlags().UintVarP(&server.updateInterval, "update", "u", 60*60*4, "Interval in seconds between downloading the framework/control data")
	metricsCmd.PersistentFlags().StringVarP(&server.scan.excludedNamespaces, "exclude-namespaces", "e", "", "Namespaces to exclude from scanning. Recommended: kube-system, kube-public")
	metricsCmd.PersistentFlags().StringVar(&server.scan.useExceptions, "exceptions", "", "Path to an exceptions obj. If not set will download exceptions from Armo management portal")
}


func logEvent(path string, r *http.Request, code int) {
	log.Printf("%s %s %s response: %d\n", r.Host, r.Method, path, code)
}

func metrics(w http.ResponseWriter, r *http.Request) {
	state.mtx.Lock()
	if !state.valid {
		w.WriteHeader(http.StatusServiceUnavailable)
		logEvent("/metrics", r, http.StatusServiceUnavailable)
	} else {
		fmt.Fprintf(w, state.response)
		logEvent("/metrics", r, 200)
	}
	state.mtx.Unlock()
}

func livez(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
	// logEvent("/livez", r, http.StatusNoContent)
}

func readyz(w http.ResponseWriter, r *http.Request) {
	state.mtx.Lock()
	if !state.valid {
		w.WriteHeader(http.StatusServiceUnavailable)
		// logEvent("/readyz", r, http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusNoContent)
		// logEvent("/readyz", r, http.StatusNoContent)
	}
	state.mtx.Unlock()
}

func backgroundScanner(scan scanDetails, interval time.Duration, update time.Duration) {
	// Scan then run timed scans
	scanner(scan, update)
	ticker := time.NewTicker(interval)
	for _ = range ticker.C {
		scanner(scan, update)
	}
}

func scanner(scan scanDetails, update time.Duration) {
	if time.Now().After(getter.GetTimestamp(getter.GetDefaultPath(getter.GetFilename(scan.name))).Add(update)) {
		log.Println("Downloading updated framework")
		cmd := exec.Command(os.Args[0], "download", scan.frameworkControl, scan.name)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, _ := cmd.Output()
		log.Printf("%s\n", out)
		log.Printf("%s\n", stderr.String())
	}
	log.Println("Running scan")
	args := []string{"scan", "-s", "-f", "prometheus", scan.frameworkControl, scan.name}
	if scan.excludedNamespaces != "" {
		args = append(args, []string{"--exclude-namespaces", scan.excludedNamespaces}...)
	}
	if scan.useExceptions != "" {
		args = append(args, []string{"--exceptions", scan.useExceptions}...)
	}
	cmd := exec.Command(os.Args[0], args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	state.mtx.Lock()
	state.response = string(out)
	if err != nil {
		state.valid = false
	} else {
		state.valid = true
	}
	state.mtx.Unlock()
	log.Printf("%s\n", stderr.String())
}
