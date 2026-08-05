package controller

import (
	"context"
	"time"

	kubescapev1 "github.com/kubescape/kubescape/v3/core/pkg/controller/apis/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type ScanScheduleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=kubescape.io,resources=scanschedules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kubescape.io,resources=scanschedules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=kubescape.io,resources=scanrequests,verbs=create;delete;get;list;watch
// +kubebuilder:rbac:groups=kubescape.io,resources=scanresults,verbs=get;list;watch;delete

func (r *ScanScheduleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var schedule kubescapev1.ScanSchedule
	if err := r.Get(ctx, req.NamespacedName, &schedule); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("ScanSchedule resource not found. Ignoring.")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get ScanSchedule")
		return ctrl.Result{}, err
	}

	if schedule.Spec.Suspend != nil && *schedule.Spec.Suspend {
		logger.Info("ScanSchedule is suspended, skipping execution")
		return ctrl.Result{}, nil
	}

	// TODO: Integrate github.com/robfig/cron/v3 to parse schedule.Spec.Schedule
	// TODO: If it's time to run, construct a new kubescapev1.ScanRequest
	//       using the data from schedule.Spec.Template.
	// TODO: List all ScanResults owned by this ScanSchedule.
	//       If the count exceeds a predefined limit, delete the oldest.

	return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
}

func (r *ScanScheduleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kubescapev1.ScanSchedule{}).
		Complete(r)
}
