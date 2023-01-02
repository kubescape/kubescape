package printer

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/gotree"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
)

const TOP_RESOURCE_COUNT = 15
const TOP_VECTOR_COUNT = 10

func (prettyPrinter *PrettyPrinter) printAttackTreeNode(node v1alpha1.IAttackTrackStep, depth int) {
	prefix := strings.Repeat("\t", depth)
	text := prefix + node.GetName() + "\n"
	if len(node.GetControls()) > 0 {
		color.Red(text)
	} else {
		color.Green(text)
	}

	for i := 0; i < node.Length(); i++ {
		prettyPrinter.printAttackTreeNode(node.SubStepAt(i), depth+1)
	}
}

func (prettyPrinter *PrettyPrinter) createFailedControlList(node v1alpha1.IAttackTrackStep) string {
	var r string
	for i, control := range node.GetControls() {
		if i == 0 {
			r = control.GetControlId()
		} else {
			r = fmt.Sprintf("%s, %s", r, control.GetControlId())
		}
	}
	return r
}

func (prettyPrinter *PrettyPrinter) buildTreeFromAttackTrackStep(tree gotree.Tree, node v1alpha1.IAttackTrackStep) gotree.Tree {
	nodeName := node.GetName()
	if len(node.GetControls()) > 0 {
		red := color.New(color.Bold, color.FgRed).SprintFunc()
		nodeName = red(nodeName)
	}

	controlText := prettyPrinter.createFailedControlList(node)
	if len(controlText) > 0 {
		controlStyle := color.New(color.FgWhite, color.Faint).SprintFunc()
		controlText = controlStyle(fmt.Sprintf(" (%s)", controlText))
	}

	subTree := gotree.New(nodeName + controlText)
	for i := 0; i < node.Length(); i++ {
		subTree.AddTree(prettyPrinter.buildTreeFromAttackTrackStep(tree, node.SubStepAt(i)))
	}

	if tree == nil {
		return subTree
	}

	tree.AddTree(subTree)
	return tree
}

func (prettyPrinter *PrettyPrinter) printResourceAttackGraph(attackTrack v1alpha1.IAttackTrack) {
	tree := prettyPrinter.buildTreeFromAttackTrackStep(nil, attackTrack.GetData())
	fmt.Fprintln(prettyPrinter.writer, tree.Print())
}

func getNumericValueFromEnvVar(envVar string, defaultValue int) int {
	value := os.Getenv(envVar)
	if value != "" {
		if value, err := strconv.Atoi(value); err == nil {
			return value
		}
	}
	return defaultValue
}
func (prettyPrinter *PrettyPrinter) printAttackTracks(opaSessionObj *cautils.OPASessionObj) {
	if prettyPrinter.printAttackTree == false || opaSessionObj.ResourceAttackTracks == nil {
		return
	}

	// check if counters are set in env vars and use them, otherwise use default values
	topResourceCount := getNumericValueFromEnvVar("ATTACK_TREE_TOP_RESOURCES", TOP_RESOURCE_COUNT)
	topVectorCount := getNumericValueFromEnvVar("ATTACK_TREE_TOP_VECTORS", TOP_VECTOR_COUNT)

	prioritizedResources := opaSessionObj.ResourcesPrioritized
	resourceToAttackTrack := opaSessionObj.ResourceAttackTracks

	resources := make([]prioritization.PrioritizedResource, 0, len(prioritizedResources))
	for _, value := range prioritizedResources {
		resources = append(resources, value)
	}

	sort.Slice(resources, func(i, j int) bool {
		return resources[i].Score > resources[j].Score
	})

	for i := 0; i < topResourceCount && i < len(resources); i++ {
		fmt.Fprintf(prettyPrinter.writer, "\n"+getSeparator("^")+"\n")
		resource := resources[i]
		resourceObj := opaSessionObj.AllResources[resource.ResourceID]

		fmt.Fprintf(prettyPrinter.writer, "Name: %s\n", resourceObj.GetName())
		fmt.Fprintf(prettyPrinter.writer, "Kind: %s\n", resourceObj.GetKind())
		fmt.Fprintf(prettyPrinter.writer, "Namespace: %s\n\n", resourceObj.GetNamespace())

		fmt.Fprintf(prettyPrinter.writer, "Score: %.2f\n", resource.Score)
		fmt.Fprintf(prettyPrinter.writer, "Severity: %s\n", apis.SeverityNumberToString(resource.Severity))
		fmt.Fprintf(prettyPrinter.writer, "Total vectors: %v\n\n", len(resources[i].PriorityVector))

		prettyPrinter.printResourceAttackGraph(resourceToAttackTrack[resource.ResourceID])

		sort.Slice(resource.PriorityVector, func(x, y int) bool {
			return resource.PriorityVector[x].Score > resource.PriorityVector[y].Score
		})

		for j := 0; j < topVectorCount && j < len(resources[i].PriorityVector); j++ {
			priorityVector := resource.PriorityVector[j]

			vectorStrings := []string{}
			for _, controlId := range priorityVector.ListControls() {
				vectorStrings = append(vectorStrings, fmt.Sprintf("%s (%s)", controlId.Category, controlId.ControlID))
			}

			fmt.Fprintf(prettyPrinter.writer, "%v) [%.2f] [Severity: %v] [Attack Track: %v]: %v \n", j+1, priorityVector.Score, apis.SeverityNumberToString(priorityVector.Severity), priorityVector.AttackTrackName, strings.Join(vectorStrings, " -> "))
		}
	}
}
