package hwmon

import "context"

func NewPlatform(_ context.Context,options Options) (*Sampler,error) {
	if options.GPU==nil {options.GPU=NewGPUSampler(5,nil,nil,nil)}
	return New(WindowsBackend{},options)
}
