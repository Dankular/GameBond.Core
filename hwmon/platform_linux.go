package hwmon

import "context"

func NewPlatform(ctx context.Context,options Options) (*Sampler,error) {return New(&LinuxBackend{Context:ctx},options)}
