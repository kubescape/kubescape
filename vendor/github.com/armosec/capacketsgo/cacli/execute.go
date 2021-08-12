package cacli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/golang/glog"
)

// RunCommand -
func runCacliCommand(arg []string, display bool) ([]byte, error) {
	cmd := &exec.Cmd{}
	command := "cacli"
	displayCommand := ""
	if display {
		displayCommand = fmt.Sprintf("command: %s %v", command, arg)
	}
	if display {
		glog.Infof("Running: %s", displayCommand)
	}
	var outb, errb bytes.Buffer
	cmd = exec.Command(command, arg...)
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		e := fmt.Sprintf("error: %v, exit code: %s. %s", cmd.Stdout, err.Error(), displayCommand)
		glog.Errorf(e)
		return nil, fmt.Errorf(e)
	}
	glog.Infof("command executed successfully. %s", displayCommand)
	return cmd.Stdout.(*bytes.Buffer).Bytes(), err
}

// runCacliCommandWithTimeout -
func runCacliCommandWithTimeout(arg []string, display bool, timeout time.Duration) ([]byte, error) {
	var outb, errb bytes.Buffer
	var cancel context.CancelFunc

	// adding timeout
	ctx := context.Background()
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := "cacli"
	if display {
		glog.Infof("Running: %s %v", command, arg)
	}

	cmd := exec.CommandContext(ctx, command, arg...)

	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf(fmt.Sprintf("stdout: %v. stderr:%v. err: %v", cmd.Stdout, cmd.Stderr, err))
		glog.Errorf("error running command, reason: %v", err.Error())
		return nil, err
	}
	return cmd.Stdout.(*bytes.Buffer).Bytes(), err
}

// RunCommand -
func RunCommand(command string, arg []string, display bool, timeout time.Duration) ([]byte, error) {
	var outb, errb bytes.Buffer
	var cancel context.CancelFunc

	// adding timeout
	ctx := context.Background()
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if display {
		glog.Infof("Running: %s %v", command, arg)
	}

	cmd := exec.CommandContext(ctx, command, arg...)

	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf(fmt.Sprintf("stdout: %v. stderr:%v. err: %v", cmd.Stdout, cmd.Stderr, err))
		glog.Errorf("error running command, reason: %v", err.Error())
		return nil, err
	}
	return cmd.Stdout.(*bytes.Buffer).Bytes(), err
}

func (cacli *Cacli) runCacliCommandRepeat(arg []string, display bool, timeout time.Duration) ([]byte, error) {
	rep, err := runCacliCommandWithTimeout(arg, display, timeout)
	if err != nil {
		if strings.Contains(err.Error(), "Name or service not known") {
			return nil, fmt.Errorf("failed to connect to Armo backend, please restart network. error: %s", err.Error())
		}
		status, _ := cacli.Status()
		if !status.LoggedIn {
			glog.Infof("logging in again and retrying %d times", 3)
			if err := cacli.cacliLogin(0); err != nil {
				return nil, err
			}
		}
		i := 0
		for i < 3 { // retry
			rep, err = runCacliCommandWithTimeout(arg, display, timeout)
			if err == nil {
				return rep, nil
			}
			i++
			time.Sleep(3 * time.Second)
		}
		// glog.Errorf("stdout: %v. stderr:%v. err: %v", cmd.Stdout, cmd.Stderr, err)
		return nil, err
	}
	return rep, nil
}

// LoginCacli -
func (cacli *Cacli) cacliLogin(retries int) error {
	if cacli.credentials.User == "" || cacli.credentials.Password == "" {
		return fmt.Errorf("Missing cacli username or password")
	}
	if err := cacli.cacliLoginRetry(retries); err != nil {
		return fmt.Errorf("failed to login, url: '%s', reason: %s", cacli.backendURL, err.Error())
	}

	status, err := cacli.Status()
	if err != nil {
		return err
	}
	s, err := json.Marshal(status)
	if err != nil {
		return err
	}
	if !status.LoggedIn {
		return fmt.Errorf("Status logged-in is false, please check your credentials")
	}
	glog.Infof("%s", string(s))
	return nil
}

// LoginCacli -
func (cacli *Cacli) cacliLoginRetry(retries int) error {
	if retries == 0 {
		retries = 1
	}

	var err error
	for i := 0; i < retries; i++ {
		if err = cacli.Login(); err == nil {
			return nil
		}
		if i != retries-1 {
			time.Sleep(3 * time.Second)
		}
	}
	return err
}

// IsLoggedIn -
func (cacli *Cacli) IsLoggedIn() (bool, error) {
	status, err := cacli.Status()
	if err != nil {
		return false, err
	}
	return status.LoggedIn, nil
}
