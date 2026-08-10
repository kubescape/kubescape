This PR resolves the issue where Kubescape fails on older clusters that do not support v1 of ValidatingAdmissionPolicies. It dynamically queries the discovery client, falls back to v1beta1, and gracefully skips if neither version is available.

Resolved #2879

My code follows the style guidelines of this project, I have commented on my code particularly in hard-to-understand areas, I have performed a self-review of my code, I have added thorough tests, and new and existing unit tests pass locally with my changes.
