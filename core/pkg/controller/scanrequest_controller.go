package controller

import (
	"context"

	kubescapev1 "github.com/kubescape/kubescape/v3/core/pkg/controller/apis/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ScanRequestReconciler reconciles a ScanRequest object
type ScanRequestReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// TODO: Inject a ScanExecutor interface here to bridge to core.Scan()
}

// +kubebuilder:rbac:groups=kubescape.io,resources=scanrequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kubescape.io,resources=scanrequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=kubescape.io,resources=scanrequests/finalizers,verbs=update

func (r *ScanRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var scanReq kubescapev1.ScanRequest
	if err := r.Get(ctx, req.NamespacedName, &scanReq); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("ScanRequest resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get ScanRequest")
		return ctrl.Result{}, err
	}

	if scanReq.Status.Phase == "Succeeded" || scanReq.Status.Phase == "Failed" {
		logger.Info("ScanRequest already finished", "phase", scanReq.Status.Phase)
		return ctrl.Result{}, nil
	}

	if scanReq.Status.Phase == "" {
		scanReq.Status.Phase = "Pending"
		if err := r.Status().Update(ctx, &scanReq); err != nil {
			logger.Error(err, "Failed to update ScanRequest status to Pending")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if scanReq.Status.Phase == "Pending" {
		logger.Info("Starting scan execution", "scanType", scanReq.Spec.ScanType)

		scanReq.Status.Phase = "Running"
		if err := r.Status().Update(ctx, &scanReq); err != nil {
			return ctrl.Result{}, err
		}

		// TODO: Call the actual core.Scan() logic via the adapter here.
		// For now, we simulate a successful scan.

		scanReq.Status.Phase = "Succeeded"
		scanReq.Status.ResultCount = 1
		if err := r.Status().Update(ctx, &scanReq); err != nil {
			logger.Error(err, "Failed to update ScanRequest status to Succeeded")
			return ctrl.Result{}, err
		}

		logger.Info("Scan completed successfully")
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ScanRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kubescapev1.ScanRequest{}).
		Complete(r)
}
