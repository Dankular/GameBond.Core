//go:build !windows

package hwmon

import "os/exec"

func hideWindow(*exec.Cmd) {}
