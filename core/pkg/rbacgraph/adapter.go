package rbacgraph

import (
	"encoding/json"
	"fmt"

	"github.com/kubescape/k8s-interface/workloadinterface"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// FromResources converts kubescape's generically-collected scan resources
// into the typed inputs NewIndex needs. Any object that is not a Role,
// ClusterRole, RoleBinding, ClusterRoleBinding, or ServiceAccount is
// ignored. An object of one of those five kinds that fails to decode is
// skipped, with its error appended to errs, rather than aborting the whole
// conversion over one bad object.
func FromResources(resources map[string]workloadinterface.IMetadata) (roles []rbacv1.Role, clusterRoles []rbacv1.ClusterRole, roleBindings []rbacv1.RoleBinding, clusterRoleBindings []rbacv1.ClusterRoleBinding, serviceAccounts []corev1.ServiceAccount, errs []error) {
	for _, resource := range resources {
		if resource == nil {
			continue
		}
		switch resource.GetKind() {
		case "Role":
			var r rbacv1.Role
			if err := decode(resource.GetObject(), &r); err != nil {
				errs = append(errs, fmt.Errorf("resource %s: %w", resource.GetID(), err))
				continue
			}
			roles = append(roles, r)
		case "ClusterRole":
			var cr rbacv1.ClusterRole
			if err := decode(resource.GetObject(), &cr); err != nil {
				errs = append(errs, fmt.Errorf("resource %s: %w", resource.GetID(), err))
				continue
			}
			clusterRoles = append(clusterRoles, cr)
		case "RoleBinding":
			var rb rbacv1.RoleBinding
			if err := decode(resource.GetObject(), &rb); err != nil {
				errs = append(errs, fmt.Errorf("resource %s: %w", resource.GetID(), err))
				continue
			}
			roleBindings = append(roleBindings, rb)
		case "ClusterRoleBinding":
			var crb rbacv1.ClusterRoleBinding
			if err := decode(resource.GetObject(), &crb); err != nil {
				errs = append(errs, fmt.Errorf("resource %s: %w", resource.GetID(), err))
				continue
			}
			clusterRoleBindings = append(clusterRoleBindings, crb)
		case "ServiceAccount":
			var sa corev1.ServiceAccount
			if err := decode(resource.GetObject(), &sa); err != nil {
				errs = append(errs, fmt.Errorf("resource %s: %w", resource.GetID(), err))
				continue
			}
			serviceAccounts = append(serviceAccounts, sa)
		}
	}
	return roles, clusterRoles, roleBindings, clusterRoleBindings, serviceAccounts, errs
}

func decode(obj map[string]any, out any) error {
	b, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}
