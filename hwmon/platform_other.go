//go:build !windows && !linux

package hwmon

import (
	"context"
	"errors"
)

func NewPlatform(context.Context,Options) (*Sampler,error) {return nil,errors.New("hardware monitoring is unavailable on this platform")}
