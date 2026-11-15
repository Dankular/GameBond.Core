package bond

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// The L3 tunnel path and the L2 bridge classify through one Classifier from different goroutines.
// Unshared, expireLearned dereferenced a nil list value and killed the client.
func TestClassifierSurvivesConcurrentUse(t *testing.T) {
	c, err := NewClassifier(nil, nil, DefaultQoSSettings())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := time.Now()
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20000; i++ {
				now := start.Add(time.Duration(i) * time.Millisecond)
				c.Classify(IPv4Info{Protocol: 6, PolicyFlow: fmt.Sprintf("f%d-%d", g, i%5000), FragmentKey: fmt.Sprintf("g%d-%d", g, i%900), FragmentOffset: i % 2}, now)
				if g == 0 && i%4000 == 0 {
					c.Reset()
				}
			}
		}(g)
	}
	wg.Wait()
}
