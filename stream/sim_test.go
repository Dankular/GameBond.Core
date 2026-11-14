package stream

import (
	"os"
	"strconv"
	"strings"
	"container/heap"
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"
)

// A deterministic virtual-time network for judging the congestion controller. Every packet
// goes out on every link (the bond duplicates, first arrival wins), each link has a rate, a
// drop-tail buffer, propagation delay, jitter, random loss and an optional rate schedule.

type simLink struct {
	rate   func(t time.Duration) float64 // bytes/second at virtual time t since start
	prop   time.Duration                 // one way
	jitter time.Duration
	maxQ   time.Duration // drop-tail buffer, as queueing delay at the current rate
	loss   float64
	spike  func(t time.Duration) time.Duration
	free   time.Time
}

func constRate(mbit float64) func(time.Duration) float64 {
	return func(time.Duration) float64 { return mbit * 1e6 / 8 }
}

type simEvent struct {
	at   time.Time
	to   int
	flow int
	b    []byte
	seq  int
}
type simQueue []simEvent

func (q simQueue) Len() int { return len(q) }
func (q simQueue) Less(i, j int) bool {
	if q[i].at.Equal(q[j].at) {
		return q[i].seq < q[j].seq
	}
	return q[i].at.Before(q[j].at)
}
func (q simQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *simQueue) Push(x any)   { *q = append(*q, x.(simEvent)) }
func (q *simQueue) Pop() any     { o := *q; n := len(o); x := o[n-1]; *q = o[:n-1]; return x }

var simTrace func(string)
var simTraceEvery = 2000

type simResult struct {
	Name           string
	Mbit           float64 // goodput after the ramp
	CapMbit        float64 // what the path could carry in the same window
	Util           float64
	MeanRTT, P95   time.Duration
	BaseRTT        time.Duration
	RetxPct        float64
	SpuriousPct    float64
	MaxCwnd        int
	Timeouts       uint64
	FlowMbit       []float64
	Chunks         int
	Jain           float64
	FirstChunk     time.Duration
	MeanChunk      time.Duration
	WorstChunk     time.Duration
	Finished       bool
	ElapsedSeconds float64
}

func (r simResult) String() string {
	if r.Chunks > 0 {
		return fmt.Sprintf("%-26s %2d chunks: first %5d ms  mean %5d ms  worst %5d ms  (avg rtt %d ms)", r.Name, r.Chunks, r.FirstChunk.Milliseconds(), r.MeanChunk.Milliseconds(), r.WorstChunk.Milliseconds(), r.MeanRTT.Milliseconds())
	}
	return fmt.Sprintf("%-26s %7.1f Mbit/s of %7.1f (%3.0f%%)  rtt mean %4d p95 %4d base %3d ms  retx %5.1f%% spur %4.1f%%  cwnd %7d  to %d",
		r.Name, r.Mbit, r.CapMbit, r.Util*100, r.MeanRTT.Milliseconds(), r.P95.Milliseconds(), r.BaseRTT.Milliseconds(), r.RetxPct, r.SpuriousPct, r.MaxCwnd, r.Timeouts)
}

type simSpec struct {
	Name    string
	Links   []simLink
	Seconds int
	Flows   int
	Cfg     Config
	Ramp    time.Duration
	// ChunkBytes > 0 makes the flow a player: fetch a chunk, idle ChunkGap, fetch the next.
	Step       time.Duration // poll interval (the endpoint ticks every millisecond)
	ChunkBytes int
	MaxChunk   time.Duration // slowest acceptable mean chunk
	ReadMbit   float64       // the application reads this slowly (0 = as fast as data arrives)
	MinUtil    float64
	MaxRetx    float64
	MaxTO      uint64
	Fair       float64 // minimum Jain fairness index across flows
	MaxRTTOver time.Duration // slowest acceptable mean queue delay over the base round trip
	ChunkGap   time.Duration
	// Allow models the transport's own per-link budget: a token bucket in bytes/second.
	AllowMbit float64
}

func (l *simLink) arrive(size int, now time.Time, start time.Time, rng *rand.Rand) (time.Time, bool) {
	t := now.Sub(start)
	rate := l.rate(t)
	if rate <= 0 {
		return time.Time{}, false
	}
	if l.free.Before(now) {
		l.free = now
	}
	if l.free.Sub(now) > l.maxQ {
		return time.Time{}, false
	}
	if l.loss > 0 && rng.Float64() < l.loss {
		return time.Time{}, false
	}
	l.free = l.free.Add(time.Duration(float64(size+28) / rate * float64(time.Second)))
	at := l.free.Add(l.prop)
	if l.spike != nil {
		at = at.Add(l.spike(t))
	}
	if l.jitter > 0 {
		at = at.Add(time.Duration(rng.Int63n(int64(l.jitter))))
	}
	return at, true
}

// runSim moves bulk data from sender to receiver on each flow and measures the sender.
func runSim(t *testing.T, s simSpec) simResult {
	t.Helper()
	rng := rand.New(rand.NewSource(11))
	links := make([]simLink, len(s.Links))
	copy(links, s.Links)
	// The return path is lightly loaded and has the same delays.
	back := make([]simLink, len(s.Links))
	for i, l := range s.Links {
		back[i] = simLink{rate: constRate(1000), prop: l.prop, jitter: l.jitter, maxQ: time.Second}
	}
	var minProp, maxProp time.Duration = time.Hour, 0
	for _, l := range s.Links {
		minProp = min(minProp, l.prop)
		maxProp = max(maxProp, l.prop)
	}
	reorder := maxProp - minProp
	var jit time.Duration
	for _, l := range s.Links {
		jit = max(jit, l.jitter)
	}
	hint := func() time.Duration { return reorder + jit }
	flows := max(s.Flows, 1)
	cfg := s.Cfg
	cfg.ReorderHint = hint
	start := time.Unix(1000, 0)
	now := start
	snd := make([]*Conn, flows)
	rcv := make([]*Conn, flows)
	for i := range snd {
		snd[i], rcv[i] = New(cfg), New(cfg)
	}
	var tokens float64
	var tokenAt = start
	if s.AllowMbit > 0 {
		c := cfg
		rate := s.AllowMbit * 1e6 / 8
		c.Allow = func(size int, at time.Time) bool {
			tokens = min(tokens+at.Sub(tokenAt).Seconds()*rate, rate*0.01+3000)
			tokenAt = at
			if tokens < float64(size) {
				return false
			}
			tokens -= float64(size)
			return true
		}
		for i := range snd {
			snd[i] = New(c)
		}
	}
	var q simQueue
	seq := 0
	push := func(at time.Time, to, flow int, b []byte) {
		seq++
		heap.Push(&q, simEvent{at, to, flow, b, seq})
	}
	// route sends one packet over every link; the first copy to arrive is the one delivered.
	route := func(set []simLink, from time.Time, to, flow int, b []byte) {
		best := time.Time{}
		ok := false
		for i := range set {
			if at, good := set[i].arrive(len(b), from, start, rng); good && (!ok || at.Before(best)) {
				best, ok = at, true
			}
		}
		if ok {
			push(best, to, flow, b)
		}
	}
	ramp := s.Ramp
	if ramp == 0 {
		ramp = 3 * time.Second
	}
	end := start.Add(time.Duration(s.Seconds) * time.Second)
	var rtts []time.Duration
	var delivered = make([]int64, flows)
	var atRamp = make([]int64, flows)
	rampDone := false
	var capBytes float64
	buf := make([]byte, 256<<10)
	chunk := make([]byte, 64<<10)
	var maxCwnd int
	var res simResult
	var chunking bool
	var chunkLeft int
	var chunkStart, nextChunk time.Time
	var chunkTarget int64
	var chunkSum time.Duration
	var readCredit float64
	step := 250 * time.Microsecond
	if s.Step > 0 {
		step = s.Step
	}
	for now.Before(end) {
		for i := 0; i < flows; i++ {
			if s.ChunkBytes > 0 {
				if !chunking && !now.Before(nextChunk) {
					chunking, chunkLeft = true, s.ChunkBytes
					chunkStart, chunkTarget = now, delivered[i]+int64(s.ChunkBytes)
				}
				for chunking && chunkLeft > 0 && snd[i].WriteSpace() > 0 {
					n, _ := snd[i].Write(chunk[:min(min(len(chunk), snd[i].WriteSpace()), chunkLeft)])
					if n == 0 {
						break
					}
					chunkLeft -= n
				}
			} else {
				for snd[i].WriteSpace() > 0 {
					n, _ := snd[i].Write(chunk[:min(len(chunk), snd[i].WriteSpace())])
					if n == 0 {
						break
					}
				}
			}
			var out [][]byte
			snd[i].Poll(now, &out)
			for _, p := range out {
				route(links, now, 1, i, p)
			}
			out = out[:0]
			rcv[i].Poll(now, &out)
			for _, p := range out {
				route(back, now, 0, i, p)
			}
		}
		now = now.Add(step)
		for q.Len() > 0 && !q[0].at.After(now) {
			e := heap.Pop(&q).(simEvent)
			if e.to == 1 {
				_ = rcv[e.flow].OnPacket(e.b, now)
			} else {
				_ = snd[e.flow].OnPacket(e.b, now)
			}
		}
		for i := 0; i < flows; i++ {
			if s.ReadMbit > 0 {
				readCredit += s.ReadMbit * 1e6 / 8 * step.Seconds()
			}
			for {
				want := len(buf)
				if s.ReadMbit > 0 {
					want = min(want, int(readCredit))
					if want <= 0 {
						break
					}
				}
				n := rcv[i].Read(buf[:want])
				if n == 0 {
					break
				}
				readCredit -= float64(n)
				delivered[i] += int64(n)
			}
			maxCwnd = max(maxCwnd, snd[i].Cwnd())
			if s.ChunkBytes > 0 && chunking && delivered[i] >= chunkTarget {
				chunking = false
				nextChunk = now.Add(s.ChunkGap)
				d := now.Sub(chunkStart)
				if res.Chunks == 0 {
					res.FirstChunk = d
				}
				res.Chunks++
				chunkSum += d
				res.WorstChunk = max(res.WorstChunk, d)
			}
		}
		if !rampDone && now.Sub(start) >= ramp {
			rampDone = true
			copy(atRamp, delivered)
		}
		if rampDone {
			// What the path could carry: the slowest link's rate (duplication = first arrival of the same bytes).
			r := links[0].rate(now.Sub(start))
			for _, l := range links {
				r = min(r, l.rate(now.Sub(start)))
			}
			if len(links) > 0 {
				// With duplication the better link wins per packet, so the best link bounds throughput.
				r = 0
				for _, l := range links {
					r = max(r, l.rate(now.Sub(start)))
				}
			}
			capBytes += r * step.Seconds()
		}
		if simTrace != nil && int(now.Sub(start)/step)%simTraceEvery == 0 {
			g := snd[0].Congestion()
			simTrace(fmt.Sprintf("t=%5.1fs %-9s bw %6.2f Mbit pace %6.2f rtprop %3dms srtt %3dms cwnd %7d inflight %7d hi %d cons %v to %d",
				now.Sub(start).Seconds(), g.Mode, g.BtlBwBps*8/1e6, g.PacingBps*8/1e6, g.RTProp.Milliseconds(), snd[0].SRTT().Milliseconds(), snd[0].Cwnd(), snd[0].InFlight(), g.InflightHi, g.Conservation, snd[0].Stats.Timeouts))
		}
		if int(now.Sub(start)/step)%40 == 0 && rampDone {
			rtts = append(rtts, snd[0].SRTT())
		}
	}
	res.Name = s.Name
	if res.Chunks > 0 {
		res.MeanChunk = chunkSum / time.Duration(res.Chunks)
	}
	secs := float64(s.Seconds) - ramp.Seconds()
	var total int64
	for i := range delivered {
		d := delivered[i] - atRamp[i]
		total += d
		res.FlowMbit = append(res.FlowMbit, float64(d)*8/secs/1e6)
	}
	res.Mbit = float64(total) * 8 / secs / 1e6
	var sum, sq float64
	for _, f := range res.FlowMbit {
		sum += f
		sq += f * f
	}
	if sq > 0 {
		res.Jain = sum * sum / (float64(len(res.FlowMbit)) * sq)
	}
	res.CapMbit = capBytes * 8 / secs / 1e6
	if res.CapMbit > 0 {
		res.Util = res.Mbit / res.CapMbit
	}
	if len(rtts) > 0 {
		sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
		var sum time.Duration
		for _, r := range rtts {
			sum += r
		}
		res.MeanRTT = sum / time.Duration(len(rtts))
		res.P95 = rtts[len(rtts)*95/100]
	}
	res.BaseRTT = 2*minProp + 0
	st := snd[0].Stats
	if st.PacketsSent > 0 {
		res.RetxPct = 100 * float64(st.Retransmits) / float64(st.PacketsSent)
		res.SpuriousPct = 100 * float64(st.SpuriousRetx) / float64(st.PacketsSent)
	}
	res.Timeouts = st.Timeouts
	res.MaxCwnd = maxCwnd
	return res
}

func simScenarios() []simSpec {
	ms := time.Millisecond
	l := func(mbit float64, prop, jit, q time.Duration, loss float64) simLink {
		return simLink{rate: constRate(mbit), prop: prop, jitter: jit, maxQ: q, loss: loss}
	}
	starlinkSpike := func(t time.Duration) time.Duration {
		if t%(5*time.Second) < 300*ms {
			return 80 * ms
		}
		return 0
	}
	steps := func(t time.Duration) float64 {
		switch {
		case t < 8*time.Second:
			return 30e6 / 8
		case t < 14*time.Second:
			return 10e6 / 8
		default:
			return 30e6 / 8
		}
	}
	return []simSpec{
		{Name: "30+25 Mbit, 20/27 ms", MaxRTTOver: 30 * ms, Seconds: 16, Links: []simLink{l(30, 20*ms, 8*ms, 250*ms, 0), l(25, 27*ms, 4*ms, 60*ms, 0)}},
		{Name: "200+200 Mbit, 25 ms", MaxRTTOver: 30 * ms, Seconds: 16, Links: []simLink{l(200, 25*ms, 4*ms, 250*ms, 0), l(200, 25*ms, 4*ms, 250*ms, 0)}},
		{Name: "5+5 Mbit", MaxRTTOver: 40 * ms, Seconds: 20, Links: []simLink{l(5, 20*ms, 4*ms, 250*ms, 0), l(5, 25*ms, 4*ms, 250*ms, 0)}},
		{Name: "1% random loss", MaxRTTOver: 30 * ms, Seconds: 16, Links: []simLink{l(30, 20*ms, 8*ms, 250*ms, .01), l(25, 27*ms, 4*ms, 60*ms, .01)}},
		{Name: "starlink spikes + loss", Seconds: 16, Links: []simLink{
			{rate: constRate(30), prop: 20 * ms, jitter: 30 * ms, maxQ: 250 * ms, loss: .01, spike: starlinkSpike},
			l(25, 27*ms, 8*ms, 60*ms, .005)}},
		{Name: "bufferbloat 20 Mbit 500ms", MaxRTTOver: 40 * ms, Seconds: 16, Links: []simLink{l(20, 25*ms, 2*ms, 500*ms, 0)}},
		{Name: "capacity 30->10->30", Seconds: 22, Links: []simLink{
			{rate: steps, prop: 20 * ms, jitter: 4 * ms, maxQ: 250 * ms}}},
		{Name: "satellite 20 Mbit 300ms", Seconds: 30, Ramp: 8 * time.Second, Links: []simLink{l(20, 300*ms, 5*ms, 400*ms, .002)}},
		{Name: "shallow buffer 30 Mbit", MaxRTTOver: 20 * ms, Seconds: 16, Links: []simLink{l(30, 20*ms, 2*ms, 15*ms, 0)}},
		{Name: "two flows share 30+25", Seconds: 20, Flows: 2, Links: []simLink{l(30, 20*ms, 8*ms, 250*ms, 0), l(25, 27*ms, 4*ms, 60*ms, 0)}},
		{Name: "player 4MB/2s on 30+25", MaxChunk: 1500 * ms, Seconds: 30, Ramp: time.Second, ChunkBytes: 4 << 20, ChunkGap: 2 * time.Second, Links: []simLink{l(30, 20*ms, 8*ms, 250*ms, 0), l(25, 27*ms, 4*ms, 60*ms, 0)}},
		{Name: "player 4MB/2s lossy 1%", MaxChunk: 1550 * ms, Seconds: 30, Ramp: time.Second, ChunkBytes: 4 << 20, ChunkGap: 2 * time.Second, Links: []simLink{l(30, 20*ms, 8*ms, 250*ms, .01), l(25, 27*ms, 4*ms, 60*ms, .01)}},
		{Name: "player 1MB/1s on 10 Mbit", MaxChunk: 1100 * ms, Seconds: 30, Ramp: time.Second, ChunkBytes: 1 << 20, ChunkGap: time.Second, Links: []simLink{l(10, 25*ms, 4*ms, 200*ms, 0)}},
		{Name: "outage 3s at t=8", Seconds: 22, MinUtil: .6, MaxTO: 12, MaxRetx: 8, Links: []simLink{{rate: func(t time.Duration) float64 {
			if t >= 8*time.Second && t < 11*time.Second {
				return 0
			}
			return 30e6 / 8
		}, prop: 20 * ms, jitter: 4 * ms, maxQ: 250 * ms}}},
		{Name: "route change +60ms at t=10", Seconds: 40, Ramp: 4 * time.Second, Links: []simLink{{rate: constRate(30), prop: 20 * ms, jitter: 4 * ms, maxQ: 250 * ms, spike: func(t time.Duration) time.Duration {
			if t >= 10*time.Second {
				return 60 * ms
			}
			return 0
		}}}},
		{Name: "5% loss 30+25", Seconds: 20, MinUtil: .6, MaxRetx: 8, Links: []simLink{l(30, 20*ms, 8*ms, 250*ms, .05), l(25, 27*ms, 4*ms, 60*ms, .05)}},
		{Name: "slow reader 5 Mbit", Seconds: 20, ReadMbit: 5, Links: []simLink{l(30, 20*ms, 8*ms, 250*ms, 0), l(25, 27*ms, 4*ms, 60*ms, 0)}},
		{Name: "8 flows share 30+25", Seconds: 30, Flows: 8, Fair: .9, Links: []simLink{l(30, 20*ms, 8*ms, 250*ms, 0), l(25, 27*ms, 4*ms, 60*ms, 0)}},
		{Name: "1 ms poll, 30+25", MaxRTTOver: 40 * ms, Seconds: 16, Step: time.Millisecond, Links: []simLink{l(30, 20*ms, 8*ms, 250*ms, 0), l(25, 27*ms, 4*ms, 60*ms, 0)}},
		{Name: "5 ms poll, 30+25", MaxRTTOver: 55 * ms, Seconds: 16, Step: 5 * time.Millisecond, Links: []simLink{l(30, 20*ms, 8*ms, 250*ms, 0), l(25, 27*ms, 4*ms, 60*ms, 0)}},
		{Name: "1 ms poll, 200+200", Seconds: 16, Step: time.Millisecond, Links: []simLink{l(200, 25*ms, 4*ms, 250*ms, 0), l(200, 25*ms, 4*ms, 250*ms, 0)}},
		{Name: "budget gate 25 Mbit on 60", Seconds: 16, AllowMbit: 25, Links: []simLink{l(60, 20*ms, 4*ms, 250*ms, 0), l(60, 27*ms, 4*ms, 250*ms, 0)}},
	}
}

func TestCongestionScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("scenario sweep")
	}
	for _, s := range simScenarios() {
		r := runSim(t, s)
		t.Log(r.String(), r.FlowMbit)
		switch {
		case s.ChunkBytes > 0:
			// A chunk should take about its size over the bottleneck, plus a few round trips.
			if r.Chunks < 5 || r.MeanChunk > s.MaxChunk {
				t.Errorf("%s: %d chunks, mean %v, want <= %v", s.Name, r.Chunks, r.MeanChunk, s.MaxChunk)
			}
		case s.AllowMbit > 0:
			if r.Mbit < 0.9*s.AllowMbit {
				t.Errorf("%s: %.1f Mbit/s under a %.0f Mbit budget", s.Name, r.Mbit, s.AllowMbit)
			}
		case s.ReadMbit > 0:
			if r.Mbit < 0.9*s.ReadMbit {
				t.Errorf("%s: %.1f Mbit/s for an application reading %.0f", s.Name, r.Mbit, s.ReadMbit)
			}
		default:
			min := 0.85
			if s.MinUtil > 0 {
				min = s.MinUtil
			}
			if r.Util < min {
				t.Errorf("%s: only %.0f%% of the path, want %.0f%%", s.Name, r.Util*100, min*100)
			}
		}
		if s.Fair > 0 && r.Jain < s.Fair {
			t.Errorf("%s: fairness %.2f, want %.2f", s.Name, r.Jain, s.Fair)
		}
		if r.Timeouts > s.MaxTO {
			t.Errorf("%s: %d whole-flight timeouts", s.Name, r.Timeouts)
		}
		retx := 3.
		if s.MaxRetx > 0 {
			retx = s.MaxRetx
		}
		if r.RetxPct > retx {
			t.Errorf("%s: %.1f%% of packets were retransmissions", s.Name, r.RetxPct)
		}
		// A standing queue hurts every other flow on the link (games share it): the mean round
		// trip must stay near the propagation delay except where capacity itself collapses.
		if s.MaxRTTOver > 0 && r.MeanRTT > r.BaseRTT+s.MaxRTTOver {
			t.Errorf("%s: mean rtt %v is %v above the base %v", s.Name, r.MeanRTT, r.MeanRTT-r.BaseRTT, r.BaseRTT)
		}
	}
}

func TestCongestionTrace(t *testing.T) {
	name := os.Getenv("SIM")
	if name == "" {
		t.Skip("set SIM to a scenario name prefix")
	}
	simTrace = func(s string) { t.Log(s) }
	if os.Getenv("EVERY") != "" {
		simTraceEvery, _ = strconv.Atoi(os.Getenv("EVERY"))
	}
	defer func() { simTrace = nil }()
	for _, s := range simScenarios() {
		if strings.HasPrefix(s.Name, name) {
			t.Log(runSim(t, s).String())
		}
	}
}
