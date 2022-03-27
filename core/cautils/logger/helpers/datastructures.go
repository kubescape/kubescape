package helpers

import "time"

type StringObj struct {
	key   string
	value string
}

type ErrorObj struct {
	key   string
	value error
}

type IntObj struct {
	key   string
	value int
}

type InterfaceObj struct {
	key   string
	value interface{}
}

func Error(e error) *ErrorObj                         { return &ErrorObj{key: "error", value: e} }
func Int(k string, v int) *IntObj                     { return &IntObj{key: k, value: v} }
func String(k, v string) *StringObj                   { return &StringObj{key: k, value: v} }
func Interface(k string, v interface{}) *InterfaceObj { return &InterfaceObj{key: k, value: v} }
func Time() *StringObj {
	return &StringObj{key: "time", value: time.Now().Format("2006-01-02 15:04:05")}
}
