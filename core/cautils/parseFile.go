package cautils

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/mikefarah/yq/v4/pkg/yqlib"
)

const (
	CommentFormat = `#This is the (?P<line>\d*) line`
)

var apiVersionRe = regexp.MustCompile(`apiVersion: (?P<apiVersion>\S*)`)
var kindRe = regexp.MustCompile(`kind: (?P<kind>\S*)`)
var pathRe = regexp.MustCompile(`path: (?P<path>\S*)`)
var typeRe = regexp.MustCompile(`type: '(?P<type>\S*)'`)
var valueRe = regexp.MustCompile(`value: (?P<value>\[.+\]|\S*)`)
var commentRe = regexp.MustCompile(CommentFormat)

// change to use go func
func GetMapping(fileName string, fileContent string) (*MappingNodes, error) {

	node := new(MappingNode)
	objectID := new(ObjectID)
	mappingNodes := new(MappingNodes)
	// mappingNodes := NewMappingNodes()
	mappingNodes.TemplateFileName = fileName

	lines := strings.Split(fileContent, "\n")

	lastNumber := -1
	reducedNumber := -1 // uses to make sure line and line in yq is the same

	isApiVersionEmpty := true
	isKindEmpty := true

	for i, line := range lines {
		index := i
		if apiVersionRe.MatchString(line) {
			apiVersion := extractParameter(apiVersionRe, line, "$apiVersion")
			if apiVersion == "" {
				err := fmt.Errorf("Something wrong when extracting the apiVersion, the line is %s\n", line)
				return nil, err
			}
			objectID.apiVersion = apiVersion
			isApiVersionEmpty = false
			if reducedNumber == -1 {
				reducedNumber = index + reducedNumber
			}
			continue
		} else if kindRe.MatchString(line) {
			kind := extractParameter(kindRe, line, "$kind")
			if kind == "" {
				err := fmt.Errorf("Something wrong when extracting the kind, the line is %s\n", line)
				return nil, err
			}
			objectID.kind = kind
			isKindEmpty = false
			continue
		} else if isApiVersionEmpty == false || isKindEmpty == false {
			// not sure if it can go to the end
			index = index - reducedNumber
			output, err := getYamlLineInfo(index, fileContent)
			if err != nil {
				err := fmt.Errorf("getYamlLineInfo wrong, the err is %s\n", err.Error())
				return nil, err
			}
			// fmt.Println(output)
			path := extractParameter(pathRe, output, "$path")
			//if path is empty, continue
			if path != "" && path != "\"\"" {
				if isApiVersionEmpty == true || isKindEmpty == true {
					err := fmt.Errorf("There is no enough objectID info")
					return nil, err
				}
				splits := strings.Split(output, "dest")
				if len(splits) < 2 {
					err := fmt.Errorf("Something wrong with the length of the splits, which is %d", len(splits))
					return nil, err
				} else {
					// cut the redundant one
					splits = splits[1:]
					for _, split := range splits {
						path := extractParameter(pathRe, split, "$path")
						pathType := extractParameter(typeRe, split, "$type")
						mapMatched, err := regexp.MatchString(`!!map`, pathType)
						if err != nil {
							err = fmt.Errorf("regexp.MatchString err: %s", err.Error())
						}
						if mapMatched {
							newlastNumber, err := writeNodeInfo(split, lastNumber, path, fileName, node, objectID, true)
							lastNumber = newlastNumber
							if err != nil {
								err = fmt.Errorf("map type: writeNodeInfo wrong err: %s", err.Error())
								return nil, err
							}
							mappingNodes.Nodes = append(mappingNodes.Nodes, *node)
						} else {
							newlastNumber, err := writeNodeInfo(split, lastNumber, path, fileName, node, objectID, false)
							lastNumber = newlastNumber
							if err != nil {
								err = fmt.Errorf("not map type: writeNodeInfo wrong err: %s", err.Error())
								return nil, err
							}
							mappingNodes.Nodes = append(mappingNodes.Nodes, *node)
						}

					}
				}
			}

		}
	}
	return mappingNodes, nil
}

func New(MappingNodes MappingNodes) {
	panic("unimplemented")
}

func writeNodeInfo(split string, lastNumber int, path string, fileName string, node *MappingNode, objectID *ObjectID, isMapType bool) (int, error) {
	value, lineNumber, newLastNumber, err := getInfoFromOne(split, lastNumber, isMapType)
	if err != nil {
		err = fmt.Errorf("getInfoFromOne wrong err: %s", err.Error())
		return -1, err
	}
	lastNumber = newLastNumber
	node.writeInfoToNode(objectID, path, lineNumber, value, fileName)
	return lastNumber, nil
}

func getInfoFromOne(output string, lastNumber int, isMapType bool) (value string, lineNumber int, newLastNumber int, err error) {
	if isMapType == true {
		value = ""
	} else {
		value = extractParameter(valueRe, output, "$value")
	}
	number := extractParameter(commentRe, output, "$line")
	if number != "" {
		lineNumber, err = strconv.Atoi(number)
		if err != nil {
			err = fmt.Errorf("strconv.Atoi err: %s", err.Error())
			return "", -1, -1, err
		}
		if isMapType == true {
			lineNumber = lineNumber - 1
		}
		lastNumber = lineNumber
		// save to structure
	} else {
		lineNumber = lastNumber
		// use the last one number
	}
	newLastNumber = lineNumber
	return value, lineNumber, newLastNumber, nil
}

func getYamlLineInfo(index int, yamlFile string) (string, error) {
	expression := `..| select(line == ` + strconv.Itoa(index) + `)| {"destpath": path | join("."),"type": type,"value": .}`
	out, err := exectuateYq(expression, yamlFile)
	if err != nil {
		err = fmt.Errorf("exectuateYq err: %s", err.Error())
		return "", err
	}
	return out, nil
}

func exectuateYq(expression string, yamlContent string) (string, error) {

	encoder := configureEncoder()

	decoder := configureDecoder(false)

	stringEvaluator := yqlib.NewStringEvaluator()

	out, err := stringEvaluator.Evaluate(expression, yamlContent, encoder, decoder)
	if err != nil {
		return "", errors.New("no matches found")
	}
	return out, err
}

func extractParameter(re *regexp.Regexp, line string, keyword string) string {
	submatch := re.FindStringSubmatchIndex(line)
	result := []byte{}
	result = re.ExpandString(result, keyword, line, submatch)
	parameter := string(result)
	return parameter
}

//yqlib configuration

func configurePrinterWriter(out io.Writer) yqlib.PrinterWriter {
	var printerWriter yqlib.PrinterWriter
	printerWriter = yqlib.NewSinglePrinterWriter(out)

	return printerWriter
}

func configureEncoder() yqlib.Encoder {
	indent := 2
	colorsEnabled := false
	yqlibEncoder := yqlib.NewYamlEncoder(indent, colorsEnabled, yqlib.ConfiguredYamlPreferences)
	return yqlibEncoder
}

func configureDecoder(evaluateTogether bool) yqlib.Decoder {
	prefs := yqlib.ConfiguredYamlPreferences
	prefs.EvaluateTogether = evaluateTogether
	yqlibDecoder := yqlib.NewYamlDecoder(prefs)
	return yqlibDecoder
}
