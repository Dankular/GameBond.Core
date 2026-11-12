package hwmon

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// Service samples on one worker. HTTP readers never enumerate processes,
// disks or GPU counters and cannot increase the sampling frequency.
type Service struct {
	mu sync.RWMutex
	latest map[string]any
	updated time.Time
	interval time.Duration
	cancel context.CancelFunc
	done chan struct{}
}

func StartService(parent context.Context,sample func()map[string]any,interval time.Duration) (*Service,error) {
	if sample==nil {return nil,fmt.Errorf("hardware sampler is required")}
	if interval<100*time.Millisecond || interval>time.Minute {return nil,fmt.Errorf("hardware sampling interval must be 100ms..1m")}
	ctx,cancel:=context.WithCancel(parent)
	s:=&Service{interval:interval,cancel:cancel,done:make(chan struct{})}
	go func(){
		defer close(s.done)
		ticker:=time.NewTicker(interval);defer ticker.Stop()
		for {
			if ctx.Err()!=nil {return}
			value:=func()(out map[string]any){defer func(){if recover()!=nil {out=map[string]any{"available":false,"errors":[]string{"Hardware sampling failed"}}}}();return sample()}()
			if value==nil {value=map[string]any{"available":false,"errors":[]string{"Hardware sample unavailable"}}}
			if _,ok:=value["available"];!ok {value["available"]=true}
			value["scope"],value["platform"]="os_visible_resources",runtime.GOOS
			s.mu.Lock();s.latest=cloneMap(value);s.updated=time.Now();s.mu.Unlock()
			select {case <-ctx.Done():return;case <-ticker.C:}
		}
	}()
	return s,nil
}

func cloneValue(v any) any {
	switch v:=v.(type) {
	case map[string]any:return cloneMap(v)
	case []map[string]any:out:=make([]map[string]any,len(v));for i,row:=range v {out[i]=cloneMap(row)};return out
	case []any:out:=make([]any,len(v));for i,item:=range v {out[i]=cloneValue(item)};return out
	case []string:return append([]string{},v...)
	default:return v
	}
}

func cloneMap(in map[string]any) map[string]any {out:=make(map[string]any,len(in));for key,value:=range in {out[key]=cloneValue(value)};return out}

func (s *Service) Snapshot() map[string]any {
	s.mu.RLock();defer s.mu.RUnlock()
	if s.latest==nil {return map[string]any{"available":false,"status":"warming_up","errors":[]string{},"history":[]any{}}}
	if time.Since(s.updated)>max(10*time.Second,3*s.interval) {return map[string]any{"available":false,"status":"stale","errors":[]string{"Hardware sample is stale"},"history":[]any{}}}
	return cloneMap(s.latest)
}

func (s *Service) Close(){s.cancel();<-s.done}

func (s *Sampler) Close() {
	if provider,ok:=s.gpu.(interface{Shutdown()});ok {provider.Shutdown()}
	if backend,ok:=s.be.(interface{Close()});ok {backend.Close()}
}
