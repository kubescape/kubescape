package apis

import (
	"encoding/json"
	"fmt"
)

// Commands list of commands received from websocket
type Commands struct {
	Commands []Command `json:"commands"`
}

// Command structure of command received from websocket
type Command struct {
	CommandName string                 `json:"commandName"`
	ResponseID  string                 `json:"responseID"`
	Wlid        string                 `json:"wlid,omitempty"`
	WildWlid    string                 `json:"wildWlid,omitempty"`
	Sid         string                 `json:"sid,omitempty"`
	WildSid     string                 `json:"wildSid,omitempty"`
	JobTracking JobTracking            `json:"jobTracking"`
	Args        map[string]interface{} `json:"args,omitempty"`
}

type JobTracking struct {
	JobID            string `json:"jobID,omitempty"`
	ParentID         string `json:"parentAction,omitempty"`
	LastActionNumber int    `json:"numSeq,omitempty"`
}

func (c *Command) DeepCopy() *Command {
	newCommand := &Command{}
	newCommand.CommandName = c.CommandName
	newCommand.ResponseID = c.ResponseID
	newCommand.Wlid = c.Wlid
	newCommand.WildWlid = c.WildWlid
	if c.Args != nil {
		newCommand.Args = make(map[string]interface{})
		for i, j := range c.Args {
			newCommand.Args[i] = j
		}
	}
	return newCommand
}

func (c *Command) GetLabels() map[string]string {
	if c.Args != nil {
		if ilabels, ok := c.Args["labels"]; ok {
			labels := map[string]string{}
			if b, e := json.Marshal(ilabels); e == nil {
				if e = json.Unmarshal(b, &labels); e == nil {
					return labels
				}
			}
		}
	}
	return map[string]string{}
}

func (c *Command) SetLabels(labels map[string]string) {
	if c.Args == nil {
		c.Args = make(map[string]interface{})
	}
	c.Args["labels"] = labels
}

func (c *Command) GetFieldSelector() map[string]string {
	if c.Args != nil {
		if ilabels, ok := c.Args["fieldSelector"]; ok {
			labels := map[string]string{}
			if b, e := json.Marshal(ilabels); e == nil {
				if e = json.Unmarshal(b, &labels); e == nil {
					return labels
				}
			}
		}
	}
	return map[string]string{}
}

func (c *Command) SetFieldSelector(labels map[string]string) {
	if c.Args == nil {
		c.Args = make(map[string]interface{})
	}
	c.Args["fieldSelector"] = labels
}

func (c *Command) GetID() string {
	if c.WildWlid != "" {
		return c.WildWlid
	}
	if c.WildSid != "" {
		return c.WildSid
	}
	if c.Wlid != "" {
		return c.Wlid
	}
	if c.Sid != "" {
		return c.Sid
	}
	return ""
}

func (c *Command) Json() string {
	b, _ := json.Marshal(*c)
	return fmt.Sprintf("%s", b)
}

func SIDFallback(c *Command) {
	if c.GetID() == "" {
		sid, err := getSIDFromArgs(c.Args)
		if err != nil || sid == "" {
			return
		}
		c.Sid = sid
	}
}

func getSIDFromArgs(args map[string]interface{}) (string, error) {
	sidInterface, ok := args["sid"]
	if !ok {
		return "", nil
	}
	sid, ok := sidInterface.(string)
	if !ok || sid == "" {
		return "", fmt.Errorf("sid found in args but empty")
	}
	// if _, err := secrethandling.SplitSecretID(sid); err != nil {
	// 	return "", err
	// }
	return sid, nil
}
