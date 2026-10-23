package cel

// The apiserver decodes a built-in kind into its Go struct before a policy
// sees it (see typedDecode), and Kubescape reads the manifest as written.
// Every case here runs in two forms so the source of a difference is
// visible (a manifest handed raw to the apiserver's validator is not a
// request the apiserver can see, so there is no raw form):
//
//   - pipeline: the apiserver gets the typed-decoded object, Kubescape the
//     manifest, which is what each does in production;
//   - typed: both sides get the typed-decoded object, which leaves only the
//     evaluators to differ.
//
// A difference present in pipeline and absent in typed is about the object
// Kubescape is handed; one present in both is about evaluation.
//
// The decode step here is typedDecode, which does not default the object. The
// apiserver does default before admission, so a field a default would add is
// outside what these cases can show.

func parityDecodeCases() []parityCase {
	forms := parityInputs(parityPipeline, parityBothTyped)
	var cases []parityCase

	podWith := func(mutate func(pod map[string]any)) func() map[string]any {
		return func() map[string]any {
			pod := parityPod()
			mutate(pod)
			return pod
		}
	}
	spec := func(pod map[string]any) map[string]any { return pod["spec"].(map[string]any) }
	meta := func(pod map[string]any) map[string]any { return pod["metadata"].(map[string]any) }
	container := func(pod map[string]any, i int) map[string]any {
		return spec(pod)["containers"].([]any)[i].(map[string]any)
	}

	type shape struct {
		name   string
		object func() map[string]any
		exprs  map[string]string
	}
	shapes := []shape{
		{"explicit-null-status", podWith(func(p map[string]any) { p["status"] = nil }), map[string]string{
			"has":        "has(object.status)",
			"is-null":    "object.status == null",
			"read-field": "has(object.status.phase)",
		}},
		{"absent-status", podWith(func(p map[string]any) {}), map[string]string{
			"has":     "has(object.status)",
			"is-null": "object.status == null",
		}},
		{"null-list", podWith(func(p map[string]any) { spec(p)["volumes"] = nil }), map[string]string{
			"has":       "has(object.spec.volumes)",
			"size":      "object.spec.volumes.size() == 0",
			"exists":    "object.spec.volumes.exists(v, true)",
			"guarded":   "!has(object.spec.volumes) || object.spec.volumes.size() == 0",
			"optional":  "object.spec.?volumes.orValue([]).size() == 0",
			"has-index": "has(object.spec.volumes) && object.spec.volumes.size() > 0",
		}},
		{"absent-list", podWith(func(p map[string]any) {}), map[string]string{
			"has":     "has(object.spec.volumes)",
			"guarded": "!has(object.spec.volumes) || object.spec.volumes.size() == 0",
		}},
		{"empty-list", podWith(func(p map[string]any) { spec(p)["volumes"] = []any{} }), map[string]string{
			"has":  "has(object.spec.volumes)",
			"size": "object.spec.volumes.size() == 0",
		}},
		{"null-map", podWith(func(p map[string]any) { meta(p)["annotations"] = nil }), map[string]string{
			"has":     "has(object.metadata.annotations)",
			"is-null": "object.metadata.annotations == null",
			"read":    "object.metadata.annotations['k'] == 'v'",
			"size":    "size(object.metadata.annotations) == 0",
		}},
		{"absent-map", podWith(func(p map[string]any) {}), map[string]string{
			"has":     "has(object.metadata.annotations)",
			"guarded": "!has(object.metadata.annotations) || size(object.metadata.annotations) == 0",
		}},
		{"empty-map", podWith(func(p map[string]any) { meta(p)["annotations"] = map[string]any{} }), map[string]string{
			"has":  "has(object.metadata.annotations)",
			"size": "size(object.metadata.annotations) == 0",
		}},
		{"null-scalar", podWith(func(p map[string]any) { spec(p)["hostNetwork"] = nil }), map[string]string{
			"has":     "has(object.spec.hostNetwork)",
			"compare": "object.spec.hostNetwork == true",
			"guarded": "has(object.spec.hostNetwork) && object.spec.hostNetwork",
		}},
		{"null-string-field", podWith(func(p map[string]any) { spec(p)["nodeName"] = nil }), map[string]string{
			"has":     "has(object.spec.nodeName)",
			"compare": "object.spec.nodeName == ''",
		}},
		{"null-nested-struct", podWith(func(p map[string]any) { spec(p)["securityContext"] = nil }), map[string]string{
			"has":       "has(object.spec.securityContext)",
			"read":      "has(object.spec.securityContext.runAsUser)",
			"is-null":   "object.spec.securityContext == null",
			"as-object": "object.spec.securityContext == {}",
		}},
		{"null-container-field", podWith(func(p map[string]any) { container(p, 0)["env"] = nil }), map[string]string{
			"has":    "has(object.spec.containers[0].env)",
			"exists": "object.spec.containers[0].env.exists(e, e.name == 'A')",
		}},
		{"null-container-struct", podWith(func(p map[string]any) { container(p, 0)["resources"] = nil }), map[string]string{
			"has":       "has(object.spec.containers[0].resources)",
			"is-null":   "object.spec.containers[0].resources == null",
			"as-object": "object.spec.containers[0].resources == {}",
		}},
		{"absent-container-struct", podWith(func(p map[string]any) {}), map[string]string{
			"has-resources":        "has(object.spec.containers[0].resources)",
			"has-resources-limits": "has(object.spec.containers[0].resources.limits)",
			"has-sidecar-security": "has(object.spec.containers[1].securityContext)",
			"has-lifecycle":        "has(object.spec.containers[0].lifecycle)",
			"has-probe":            "has(object.spec.containers[0].livenessProbe)",
		}},
		{"empty-container-struct", podWith(func(p map[string]any) { container(p, 0)["resources"] = map[string]any{} }), map[string]string{
			"has":        "has(object.spec.containers[0].resources)",
			"has-limits": "has(object.spec.containers[0].resources.limits)",
		}},
		{"null-list-element", podWith(func(p map[string]any) { container(p, 0)["args"] = []any{nil, "x"} }), map[string]string{
			"size":  "object.spec.containers[0].args.size() == 2",
			"first": "object.spec.containers[0].args[0] == ''",
			"null":  "object.spec.containers[0].args[0] == null",
		}},
		{"null-map-entry", podWith(func(p map[string]any) { meta(p)["labels"] = map[string]any{"a": nil, "b": "x"} }), map[string]string{
			"key-kept": "'a' in object.metadata.labels",
			"empty":    "object.metadata.labels['a'] == ''",
			"null":     "object.metadata.labels['a'] == null",
		}},
		{"unknown-field", podWith(func(p map[string]any) { spec(p)["bogusField"] = "x" }), map[string]string{
			"has":  "has(object.spec.bogusField)",
			"read": "object.spec.bogusField == 'x'",
		}},
		{"creation-timestamp", podWith(func(p map[string]any) { meta(p)["creationTimestamp"] = nil }), map[string]string{
			"has":     "has(object.metadata.creationTimestamp)",
			"is-null": "object.metadata.creationTimestamp == null",
		}},
		{"absent-creation-timestamp", podWith(func(p map[string]any) {}), map[string]string{
			"has": "has(object.metadata.creationTimestamp)",
		}},
	}
	for _, s := range shapes {
		for name, expr := range s.exprs {
			cases = append(cases, parityNew(s.name+"/"+name, parityCatDecode, forms, parityObjectOf(s.object, "pods"), parityExprs(expr)))
		}
	}

	// Namespace data reaches the apiserver typed whatever the form of the
	// object, so only Kubescape's copy follows the input form.
	nsWith := func(mutate func(ns map[string]any)) parityOption {
		return func(c *parityCase) {
			c.Namespace = func() map[string]any {
				ns := parityNamespace()
				mutate(ns)
				return ns
			}
		}
	}
	nsMeta := func(ns map[string]any) map[string]any { return ns["metadata"].(map[string]any) }
	nsShapes := []struct {
		name   string
		option parityOption
		exprs  map[string]string
	}{
		{"manifest-without-spec-or-status", nsWith(func(map[string]any) {}), map[string]string{
			"has-spec":   "has(namespaceObject.spec)",
			"has-status": "has(namespaceObject.status)",
			"has-phase":  "has(namespaceObject.status.phase)",
			"has-final":  "has(namespaceObject.spec.finalizers)",
		}},
		{"null-labels", nsWith(func(ns map[string]any) { nsMeta(ns)["labels"] = nil }), map[string]string{
			"has":     "has(namespaceObject.metadata.labels)",
			"is-null": "namespaceObject.metadata.labels == null",
			"read":    "namespaceObject.metadata.labels.env == 'prod'",
		}},
		{"null-annotations", nsWith(func(ns map[string]any) { nsMeta(ns)["annotations"] = nil }), map[string]string{
			"has":     "has(namespaceObject.metadata.annotations)",
			"is-null": "namespaceObject.metadata.annotations == null",
		}},
		{"null-spec", nsWith(func(ns map[string]any) { ns["spec"] = nil }), map[string]string{
			"has":     "has(namespaceObject.spec)",
			"is-null": "namespaceObject.spec == null",
		}},
		{"null-status", nsWith(func(ns map[string]any) { ns["status"] = nil }), map[string]string{
			"has":     "has(namespaceObject.status)",
			"is-null": "namespaceObject.status == null",
		}},
		{"empty-labels", nsWith(func(ns map[string]any) { nsMeta(ns)["labels"] = map[string]any{} }), map[string]string{
			"has":  "has(namespaceObject.metadata.labels)",
			"size": "size(namespaceObject.metadata.labels) == 0",
		}},
		{"null-creation-timestamp", nsWith(func(ns map[string]any) { nsMeta(ns)["creationTimestamp"] = nil }), map[string]string{
			"has": "has(namespaceObject.metadata.creationTimestamp)",
		}},
		{"populated-status", nsWith(func(ns map[string]any) { ns["status"] = map[string]any{"phase": "Active"} }), map[string]string{
			"phase": "namespaceObject.status.phase == 'Active'",
		}},
	}
	for _, s := range nsShapes {
		for name, expr := range s.exprs {
			cases = append(cases, parityNew("namespace-"+s.name+"/"+name, parityCatDecode, forms, s.option, parityExprs(expr)))
		}
	}

	// A custom resource is handed to a policy as written, so a null a CRD
	// schema marks nullable survives on both sides.
	for name, expr := range map[string]string{
		"null-kept":       "object.spec.tags == null",
		"has-null":        "has(object.spec.tags)",
		"empty-struct":    "has(object.spec.nested)",
		"absent-struct":   "has(object.spec.other)",
		"number-is-int":   "object.spec.replicas == 2",
		"number-is-typed": "type(object.spec.replicas) == int",
	} {
		cases = append(cases, parityNew("custom-resource/"+name, parityCatDecode, forms, parityObjectOf(parityCustomResource, "widgets"), parityExprs(expr)))
	}

	// Objects other than a Pod, to avoid reading the Pod-shaped result as the
	// rule for every kind.
	cases = append(cases,
		parityNew("deployment/absent-strategy", parityCatDecode, forms, parityObjectOf(parityDeployment, "deployments"), parityExprs("has(object.spec.strategy)", "has(object.status)", "has(object.spec.template.spec.securityContext)")),
		parityNew("config-map/null-data", parityCatDecode, forms, parityObjectOf(func() map[string]any {
			cm := parityConfigMap()
			cm["data"] = nil
			return cm
		}, "configmaps"), parityExprs("has(object.data)")),
	)
	return cases
}
