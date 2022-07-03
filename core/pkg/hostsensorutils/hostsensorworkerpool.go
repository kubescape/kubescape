package hostsensorutils

import (
	"sync"

	"github.com/armosec/kubescape/v2/core/cautils/logger"
	"github.com/armosec/kubescape/v2/core/cautils/logger/helpers"
	"github.com/armosec/opa-utils/objectsenvelopes/hostsensor"
)

const noOfWorkers int = 10

type Job struct {
	podName     string
	nodeName    string
	requestKind string
	path        string
}

type workerPool struct {
	jobs    chan Job
	results chan hostsensor.HostSensorDataEnvelope
	Done    chan bool
}

func NewWorkerPool() workerPool {
	wp := workerPool{}
	wp.init()
	return wp
}

func (wp *workerPool) init() {
	// init the channels
	wp.jobs = make(chan Job, noOfWorkers)
	wp.results = make(chan hostsensor.HostSensorDataEnvelope, noOfWorkers)
	wp.Done = make(chan bool)
}

// The worker takes a job out of the chan, executes the request, and pushes the result to the results chan
func (wp *workerPool) hostSensorWorker(hsh *HostSensorHandler, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range wp.jobs {
		hostSensorDataEnvelope, err := hsh.getResourcesFromPod(job.podName, job.nodeName, job.requestKind, job.path)
		if err != nil {
			logger.L().Error("failed to get data", helpers.String("path", job.path), helpers.String("podName", job.podName), helpers.Error(err))
		} else {
			wp.results <- hostSensorDataEnvelope
		}
	}
}

func (wp *workerPool) createWorkerPool(hsh *HostSensorHandler, wg *sync.WaitGroup) {
	for i := 0; i < noOfWorkers; i++ {
		wg.Add(1)
		go wp.hostSensorWorker(hsh, wg)
	}
}

func (wp *workerPool) waitForDone(wg *sync.WaitGroup) {
	// Waiting for workers to finish
	wg.Wait()
	close(wp.results)

	// Waiting for the results to be processed
	<-wp.Done
}

func (wp *workerPool) hostSensorGetResults(result *[]hostsensor.HostSensorDataEnvelope) {
	go func() {
		for res := range wp.results {
			*result = append(*result, res)
		}
		wp.Done <- true
	}()
}

func (wp *workerPool) hostSensorApplyJobs(podList map[string]string, path, requestKind string) {
	go func() {
		for podName, nodeName := range podList {
			job := Job{
				podName:     podName,
				nodeName:    nodeName,
				requestKind: requestKind,
				path:        path,
			}
			wp.jobs <- job

		}
		close(wp.jobs)
	}()
}
