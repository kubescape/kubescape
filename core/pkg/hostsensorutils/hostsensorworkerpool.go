package hostsensorutils

import (
	"context"
	"sync"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
)

const noOfWorkers int = 10

type job struct {
	podName     string
	nodeName    string
	requestKind scannerResource
	path        string
}

type workerPool struct {
	jobs        chan job
	results     chan hostsensor.HostSensorDataEnvelope
	done        chan bool
	noOfWorkers int
}

func newWorkerPool() workerPool {
	wp := workerPool{}
	wp.noOfWorkers = noOfWorkers
	wp.init()
	return wp
}

func (wp *workerPool) init(noOfPods ...int) {
	if len(noOfPods) > 0 && noOfPods[0] < noOfWorkers {
		wp.noOfWorkers = noOfPods[0]
	}
	// init the channels
	wp.jobs = make(chan job, noOfWorkers)
	wp.results = make(chan hostsensor.HostSensorDataEnvelope, noOfWorkers)
	wp.done = make(chan bool)
}

// The worker takes a job out of the chan, executes the request, and pushes the result to the results chan
func (wp *workerPool) hostSensorWorker(ctx context.Context, hsh *HostSensorHandler, wg *sync.WaitGroup, log *LogsMap) {
	defer wg.Done()
	for job := range wp.jobs {
		hostSensorDataEnvelope, err := hsh.getResourcesFromPod(job.podName, job.nodeName, job.requestKind, job.path)
		if err != nil && !log.isDuplicated(failedToGetData) {
			logger.L().Ctx(ctx).Warning(failedToGetData, helpers.String("path", job.path), helpers.Error(err))
			log.update(failedToGetData)
			continue
		}
		wp.results <- hostSensorDataEnvelope
	}
}

func (wp *workerPool) createWorkerPool(ctx context.Context, hsh *HostSensorHandler, wg *sync.WaitGroup, log *LogsMap) {
	for i := 0; i < noOfWorkers; i++ {
		wg.Add(1)
		go wp.hostSensorWorker(ctx, hsh, wg, log)
	}
}

func (wp *workerPool) waitForDone(wg *sync.WaitGroup) {
	// Waiting for workers to finish
	wg.Wait()
	close(wp.results)

	// Waiting for the results to be processed
	<-wp.done
}

func (wp *workerPool) hostSensorGetResults(result *[]hostsensor.HostSensorDataEnvelope) {
	go func() {
		for res := range wp.results {
			*result = append(*result, res)
		}
		wp.done <- true
	}()
}

func (wp *workerPool) hostSensorApplyJobs(podList map[string]string, path string, requestKind scannerResource) {
	go func() {
		for podName, nodeName := range podList {
			thisJob := job{
				podName:     podName,
				nodeName:    nodeName,
				requestKind: requestKind,
				path:        path,
			}
			wp.jobs <- thisJob

		}
		close(wp.jobs)
	}()
}
