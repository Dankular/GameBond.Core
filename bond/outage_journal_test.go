package bond

import (
	"os"
	"testing"
	"time"
)

func TestOutageJournalRecordsLinkAndFullOutages(t *testing.T) {
	r := &Receiver{outages: newOutageJournal(), paths: map[PathKey]*receivePath{}}
	a := &receivePath{local: 0, ready: true}
	b := &receivePath{local: 1, ready: true}
	r.paths[PathKey{Local: 0}] = a
	r.paths[PathKey{Local: 1}] = b
	t0 := time.Unix(1000, 0)
	frame := func(hears byte) []byte { return []byte{hears, bfdMultiplier, 100, 0, 0, 0, 0, 0} }
	r.bfdReceived(a, frame(1), t0)
	r.bfdReceived(b, frame(1), t0)

	r.bfdReceived(a, frame(0), t0.Add(time.Second)) // A drops, B still carries
	if s := r.Outages(); s.NoLinksNow || s.NoLinksCount != 0 || len(s.Events) != 1 || s.Events[0].Kind != OutageLinkDown || s.Events[0].Slot != 0 {
		t.Fatalf("%+v", s)
	}
	r.bfdReceived(b, frame(0), t0.Add(2*time.Second)) // B drops too: nothing carries
	if s := r.Outages(); !s.NoLinksNow || s.NoLinksCount != 1 {
		t.Fatalf("full outage not recorded: %+v", s)
	}
	for i := 0; i < 40; i++ { // both recover after their hold-down
		at := t0.Add(2*time.Second + time.Duration(i)*100*time.Millisecond)
		r.bfdReceived(a, frame(1), at)
		r.bfdReceived(b, frame(1), at)
	}
	s := r.Outages()
	if s.NoLinksNow || s.NoLinksMaxMS < 200 {
		t.Fatalf("recovery not recorded: %+v", s)
	}
	kinds := map[string]int{}
	for _, e := range s.Events {
		kinds[e.Kind]++
	}
	if kinds[OutageNoLinks] != 1 || kinds[OutageLinksRestored] != 1 || kinds[OutageLinkUp] != 2 || kinds[OutageLinkDown] != 2 {
		t.Fatalf("%v", kinds)
	}
}

func TestOutageJournalIsBounded(t *testing.T) {
	j := newOutageJournal()
	for i := 0; i < 3*outageJournalSize; i++ {
		j.Record(time.Unix(int64(i), 0), 0, OutageLinkDown, "silence", 0)
	}
	ev := j.Events()
	if len(ev) != outageJournalSize || ev[len(ev)-1].AtMS != int64(3*outageJournalSize-1)*1000 || ev[0].AtMS >= ev[1].AtMS {
		t.Fatalf("len %d first %d last %d", len(ev), ev[0].AtMS, ev[len(ev)-1].AtMS)
	}
}

func TestOutageLogIsDurableCappedAndNonBlocking(t *testing.T) {
	dir := t.TempDir()
	l, err := openOutageLog(dir, 24*100, 3) // 100 records per segment, keep 3
	if err != nil {
		t.Fatal(err)
	}
	j := newOutageJournal()
	j.log = l
	base := time.Unix(5000, 0)
	const n = 1000
	for i := 0; i < n; i++ {
		j.Record(base.Add(time.Duration(i)*time.Millisecond), i%2, OutageLinkDown, "silence", time.Duration(i)*time.Millisecond)
	}
	j.mu.Lock()
	j.log = nil
	j.mu.Unlock()
	l.close()
	info := l.info()
	if info.Written+info.Dropped != n {
		t.Fatalf("written %d + dropped %d != %d", info.Written, info.Dropped, n)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) > 3 {
		t.Fatalf("%d segments kept, cap 3", len(ents))
	}
	got, err := ReadOutageLog(dir, 5, nil)
	if err != nil || len(got) != 5 {
		t.Fatalf("%v %d", err, len(got))
	}
	if got[4].Seq != j.seq || got[4].Kind != OutageLinkDown || got[4].Cause != "silence" || got[0].AtMS >= got[4].AtMS {
		t.Fatalf("%+v", got)
	}
	one, _ := ReadOutageLog(dir, 3, func(e OutageEvent) bool { return e.Slot == 1 })
	for _, e := range one {
		if e.Slot != 1 {
			t.Fatalf("filter ignored: %+v", e)
		}
	}
}

func TestOutageTotalsAndSnapshotCache(t *testing.T) {
	j := newOutageJournal()
	now := time.Now()
	for i := 0; i < 5000; i++ {
		j.Record(now, 0, OutageLinkDown, "silence", 0)
	}
	s := j.Summary()
	if s.TotalEvents != 5000 || s.LinkDowns != 5000 || len(s.Events) != outageSnapshotLen || s.SlotDowns[0] != 5000 || s.DownsLastHour != 5000 {
		t.Fatalf("%+v", s)
	}
	if &j.Summary().Events[0] != &s.Events[0] {
		t.Fatal("snapshot rebuilt although nothing changed")
	}
	if n := len(j.Events()); n != outageJournalSize {
		t.Fatalf("ring grew to %d", n)
	}
}

func BenchmarkOutageRecordWithLog(b *testing.B) {
	l, err := openOutageLog(b.TempDir(), outageSegmentBytes, outageMaxSegments)
	if err != nil {
		b.Fatal(err)
	}
	j := newOutageJournal()
	j.log = l
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j.Record(now, i&1, OutageLinkDown, "silence", 0)
	}
	b.StopTimer()
	j.mu.Lock()
	j.log = nil
	j.mu.Unlock()
	l.close()
	b.ReportMetric(float64(l.info().Dropped)/float64(b.N)*100, "%dropped")
}

func TestComponentHealthIsEdgeTriggeredAndBounded(t *testing.T) {
	j := newOutageJournal()
	t0 := time.Unix(9000, 0)
	j.Component(t0, "driver:packet_filter", true, "") // healthy at first sight: remembered, not journalled
	for i := 0; i < 1000; i++ {                      // polling an unchanged state costs nothing
		j.Component(t0.Add(time.Duration(i)*time.Millisecond), "driver:packet_filter", true, "")
	}
	if n := len(j.Events()); n != 0 {
		t.Fatalf("%d events for a healthy, unchanged component", n)
	}
	j.Component(t0.Add(time.Second), "driver:packet_filter", false, "stopped")
	j.Component(t0.Add(2*time.Second), "driver:packet_filter", false, "stopped") // still failing: no new event
	j.ComponentError(t0.Add(3*time.Second), "nic:Ethernet", "+12 errors")
	j.Component(t0.Add(4*time.Second), "driver:packet_filter", true, "")
	ev := j.Events()
	if len(ev) != 3 || ev[0].Kind != OutageComponentDown || ev[1].Kind != OutageComponentError || ev[2].Kind != OutageComponentUp || ev[2].DownMS != 3000 || ev[0].Slot != -1 {
		t.Fatalf("%+v", ev)
	}
	s := j.Summary()
	if s.ComponentFails != 1 || len(s.Components) != 2 {
		t.Fatalf("%+v", s.Components)
	}
	for i := 0; i < 500; i++ {
		j.Component(t0, "nic:"+string(rune('a'+i%26))+string(rune('a'+i/26%26)), false, "x")
	}
	if n := len(j.Summary().Components); n > maxComponents+1 {
		t.Fatalf("component table grew to %d", n)
	}
}

func TestComponentEventsSurviveTheDurableLog(t *testing.T) {
	dir := t.TempDir()
	l, err := openOutageLog(dir, outageSegmentBytes, 2)
	if err != nil {
		t.Fatal(err)
	}
	j := newOutageJournal()
	j.log = l
	j.Component(time.Unix(1, 0), "nic:Ethernet", false, "no_media")
	j.mu.Lock()
	j.log = nil
	j.mu.Unlock()
	l.close()
	got, err := ReadOutageLog(dir, 10, nil)
	if err != nil || len(got) != 1 || got[0].Source != "nic:Ethernet" || got[0].Note != "no_media" || got[0].Slot != -1 || got[0].Kind != OutageComponentDown {
		t.Fatalf("%v %+v", err, got)
	}
}
