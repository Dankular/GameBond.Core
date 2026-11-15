package bond

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestRSTPParticipantBlocksUntilRapidAgreementAndEdgeForwards(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	local := NewL2Switch(L2SwitchConfig{RSTPEnabled: true, BridgePriority: 32768, BridgeMAC: [6]byte{2, 0, 0, 0, 0, 2}, Ports: []L2PortConfig{{ID: 1, RSTPParticipant: true}, {ID: 2, RSTPParticipant: true, RSTPEdge: true}}})
	if got := local.Forward(1, testRSTPDataFrame(), base); got.Drop != L2DropRSTP {
		t.Fatalf("startup non-edge port: got drop %q", got.Drop)
	}
	if got := local.Forward(2, testRSTPDataFrame(), base); got.Drop != L2Forward {
		t.Fatalf("edge port should fast-forward: got drop %q", got.Drop)
	}
	remote := NewL2Switch(L2SwitchConfig{RSTPEnabled: true, BridgePriority: 4096, BridgeMAC: [6]byte{2, 0, 0, 0, 0, 1}, Ports: []L2PortConfig{{ID: 1, RSTPParticipant: true}}})
	bpdus := remote.DueRSTPBPDUs(base)
	if len(bpdus[1]) == 0 {
		t.Fatal("root bridge did not emit initial designated BPDU")
	}
	if verdict := local.Forward(1, bpdus[1], base.Add(time.Millisecond)); verdict.Drop != L2Forward {
		t.Fatalf("BPDU must be consumed, got %q", verdict.Drop)
	}
	role, state := local.RSTPPortState(1)
	if role != RSTPRoleRoot || state != RSTPStateForwarding {
		t.Fatalf("got root port role=%s state=%s", role, state)
	}
	if got := local.Forward(1, testRSTPDataFrame(), base.Add(2*time.Millisecond)); got.Drop != L2Forward {
		t.Fatalf("agreed root port should forward, got %q", got.Drop)
	}
	status := local.RSTPStatus()
	if !status.Enabled || status.RootPathCost == 0 || status.RootPort != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestRSTPBPDUTransmitIsDirectAndConfigRejectsGuardConflict(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	sw := NewL2Switch(L2SwitchConfig{RSTPEnabled: true, BridgeMAC: [6]byte{2, 0, 0, 0, 0, 2}, Ports: []L2PortConfig{{ID: 1, RSTPParticipant: true}}})
	bpdus := sw.DueRSTPBPDUs(now)
	if len(bpdus) != 1 {
		t.Fatalf("due BPDUs = %v, want one designated port", bpdus)
	}
	info, err := ParseFrame(bpdus[1])
	if err != nil || !info.BPDU {
		t.Fatalf("invalid generated BPDU, info=%+v err=%v", info, err)
	}
	if len(bpdus[1]) < 60 {
		t.Fatalf("generated RSTP frame length=%d, want Ethernet minimum 60 without FCS", len(bpdus[1]))
	}
	if err := (L2SwitchConfig{RSTPEnabled: true, Ports: []L2PortConfig{{ID: 1, RSTPParticipant: true, BPDUGuard: true}}}).Validate(); err == nil {
		t.Fatal("expected BPDU guard/RSTP conflict validation")
	}
}

func TestRSTPSharedLinkUsesForwardDelayAndPriorityZeroCanBeConfigured(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	sw := NewL2Switch(L2SwitchConfig{RSTPEnabled: true, BridgePrioritySet: true, BridgeMAC: [6]byte{2, 0, 0, 0, 0, 2}, RSTPHelloTime: time.Second, RSTPMaxAge: 6 * time.Second, RSTPForwardDelay: 4 * time.Second, Ports: []L2PortConfig{{ID: 1, RSTPParticipant: true, RSTPSharedLink: true}, {ID: 2}}})
	if got := sw.RSTPStatus(); got.BridgeID[:4] != "0000" {
		t.Fatalf("configured priority zero was not honored: %s", got.BridgeID)
	}
	if got := sw.Forward(1, testRSTPDataFrame(), now); got.Drop != L2DropRSTP {
		t.Fatalf("shared port should start discarding, got %q", got.Drop)
	}
	if got := sw.Forward(1, testRSTPDataFrame(), now.Add(4*time.Second)); got.Drop != L2DropRSTP {
		t.Fatalf("shared port should learn before forwarding, got %q", got.Drop)
	}
	role, state := sw.RSTPPortState(1)
	if role != RSTPRoleDesignated || state != RSTPStateLearning {
		t.Fatalf("after one forward delay role/state=%s/%s", role, state)
	}
	if got := sw.Forward(1, testRSTPDataFrame(), now.Add(8*time.Second)); got.Drop != L2Forward {
		t.Fatalf("shared port should forward after two delays, got %q", got.Drop)
	}
}

func TestRSTPBPDUValidatesTimerBoundsAndPropagatesRootTimers(t *testing.T) {
	now := time.Unix(100, 0)
	root, err := NewL2SwitchChecked(L2SwitchConfig{
		RSTPEnabled: true, BridgePriority: 4096, BridgeMAC: [6]byte{2, 0, 0, 0, 0, 1},
		RSTPHelloTime: 3 * time.Second, RSTPMaxAge: 20 * time.Second, RSTPForwardDelay: 15 * time.Second,
		Ports: []L2PortConfig{{ID: 1, RSTPParticipant: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rapid := root.DueRSTPBPDUs(now)[1]
	legacy := makeSTPConfigBPDU(RSTPBridgeID{Priority: 4096, MAC: [6]byte{2, 0, 0, 0, 0, 1}}, 0, 1, 0)
	if _, err := parseRSTPBPDU(rapid); err != nil {
		t.Fatalf("valid rapid BPDU rejected: %v", err)
	}
	if _, err := parseRSTPBPDU(legacy); err != nil {
		t.Fatalf("valid legacy BPDU rejected: %v", err)
	}

	mutations := []struct {
		name  string
		apply func([]byte)
	}{
		{"zero hello", func(frame []byte) { putRSTPTimer(frame[48:50], 0) }},
		{"hello too large", func(frame []byte) { putRSTPTimer(frame[48:50], 11*time.Second) }},
		{"max age too small", func(frame []byte) { putRSTPTimer(frame[46:48], 5*time.Second) }},
		{"max age too large", func(frame []byte) { putRSTPTimer(frame[46:48], 41*time.Second) }},
		{"forward delay too small", func(frame []byte) { putRSTPTimer(frame[50:52], 3*time.Second) }},
		{"forward delay too large", func(frame []byte) { putRSTPTimer(frame[50:52], 31*time.Second) }},
		{"max age below hello relationship", func(frame []byte) {
			putRSTPTimer(frame[46:48], 6*time.Second)
			putRSTPTimer(frame[48:50], 3*time.Second)
		}},
		{"max age above forward relationship", func(frame []byte) {
			putRSTPTimer(frame[46:48], 40*time.Second)
			putRSTPTimer(frame[50:52], 15*time.Second)
		}},
		{"message age reaches max age", func(frame []byte) { putRSTPTimer(frame[44:46], 20*time.Second) }},
	}
	for _, base := range []struct {
		name  string
		frame []byte
	}{{"rapid", rapid}, {"legacy", legacy}} {
		for _, mutation := range mutations {
			t.Run(base.name+"/"+mutation.name, func(t *testing.T) {
				frame := append([]byte(nil), base.frame...)
				mutation.apply(frame)
				if _, err := parseRSTPBPDU(frame); err == nil {
					t.Fatal("invalid timer parameters were accepted")
				}
			})
		}
	}

	local := NewL2Switch(L2SwitchConfig{RSTPEnabled: true, BridgePriority: 32768, BridgeMAC: [6]byte{2, 0, 0, 0, 0, 2}, Ports: []L2PortConfig{{ID: 1, RSTPParticipant: true}}})
	if verdict := local.Forward(1, rapid, now); verdict.Drop != L2Forward {
		t.Fatalf("valid root BPDU was not consumed: %+v", verdict)
	}
	maxAge, hello, forward := local.rstp.rootTimers()
	if maxAge != 20*time.Second || hello != 3*time.Second || forward != 15*time.Second {
		t.Fatalf("root timer values were not propagated: maxAge=%v hello=%v forward=%v", maxAge, hello, forward)
	}
}

func TestRSTPPeerExpiresAfterRemainingMessageAgeLifetime(t *testing.T) {
	now := time.Unix(200, 0)
	remote := NewL2Switch(L2SwitchConfig{
		RSTPEnabled: true, BridgePriority: 4096, BridgeMAC: [6]byte{2, 0, 0, 0, 0, 1},
		Ports: []L2PortConfig{{ID: 1, RSTPParticipant: true}},
	})
	frame := remote.DueRSTPBPDUs(now)[1]
	putRSTPTimer(frame[44:46], 18*time.Second)
	local := NewL2Switch(L2SwitchConfig{
		RSTPEnabled: true, BridgePriority: 32768, BridgeMAC: [6]byte{2, 0, 0, 0, 0, 2},
		Ports: []L2PortConfig{{ID: 1, RSTPParticipant: true}},
	})
	if verdict := local.Forward(1, frame, now); verdict.Drop != L2Forward {
		t.Fatalf("valid aged root BPDU was rejected: %+v", verdict)
	}
	if got := local.RSTPStatus().RootPort; got != 1 {
		t.Fatalf("root port = %d immediately after BPDU, want 1", got)
	}
	local.DueRSTPBPDUs(now.Add(time.Second))
	if got := local.RSTPStatus().RootPort; got != 1 {
		t.Fatalf("root information expired before remaining lifetime elapsed: root port=%d", got)
	}
	local.DueRSTPBPDUs(now.Add(2 * time.Second))
	if got := local.RSTPStatus().RootPort; got != 0 {
		t.Fatalf("aged root information remained after MaxAge-MessageAge: root port=%d", got)
	}
}

func TestRSTPTopologyChangeFlushScopeDampeningAndPropagationExpiry(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	local := NewL2Switch(L2SwitchConfig{RSTPEnabled: true, BridgeMAC: [6]byte{2, 0, 0, 0, 0, 2}, Ports: []L2PortConfig{
		{ID: 1, RSTPParticipant: true, RSTPEdge: true},
		{ID: 2, RSTPParticipant: true, RSTPEdge: true},
		{ID: 3}, // Unrelated service port is outside the RSTP flush scope.
		{ID: 4}, // Egress for test broadcasts.
	}})
	learnRSTPTestMAC(t, local, 1, 1, base)
	learnRSTPTestMAC(t, local, 2, 2, base)
	learnRSTPTestMAC(t, local, 3, 3, base)

	peer := NewL2Switch(L2SwitchConfig{RSTPEnabled: true, BridgePriority: 4096, BridgeMAC: [6]byte{2, 0, 0, 0, 0, 1}, Ports: []L2PortConfig{{ID: 1, RSTPParticipant: true}}})
	tc := peer.DueRSTPBPDUs(base)[1]
	tc[21] |= rstpFlagTC // RSTP flags byte in the LLC BPDU.
	local.Forward(1, tc, base.Add(10*time.Millisecond))
	assertLearnedPort(t, local, 1, 1, true)  // ingress path is retained
	assertLearnedPort(t, local, 2, 2, false) // other spanning-tree path is flushed
	assertLearnedPort(t, local, 3, 3, true)  // nonparticipant/service path is retained

	// A repeated TC within one hello interval refreshes propagation but must not
	// repeatedly flush a MAC relearned behind the other participant port.
	learnRSTPTestMAC(t, local, 2, 2, base.Add(20*time.Millisecond))
	local.Forward(1, tc, base.Add(100*time.Millisecond))
	assertLearnedPort(t, local, 2, 2, true)

	// Designated downstream ports propagate TC for two hello times, then stop.
	propagated := local.DueRSTPBPDUs(base.Add(101 * time.Millisecond))[2]
	if len(propagated) == 0 || propagated[21]&rstpFlagTC == 0 {
		t.Fatal("designated egress did not propagate active TC")
	}
	if later := local.DueRSTPBPDUs(base.Add(5 * time.Second))[2]; len(later) == 0 || later[21]&rstpFlagTC != 0 {
		t.Fatalf("TC should expire from egress BPDUs after propagation window: flags=%02x", later[21])
	}

	// After the dampening interval, a fresh TC flushes the participant path again.
	learnRSTPTestMAC(t, local, 2, 2, base.Add(3*time.Second))
	local.Forward(1, tc, base.Add(3*time.Second))
	assertLearnedPort(t, local, 2, 2, false)
}

func learnRSTPTestMAC(t *testing.T, sw *L2Switch, port PortID, suffix byte, now time.Time) {
	t.Helper()
	frame := testRSTPDataFrame()
	frame[11] = suffix
	if verdict := sw.Forward(port, frame, now); verdict.Drop != L2Forward {
		t.Fatalf("learn on port %d dropped: %s", port, verdict.Drop)
	}
}

func assertLearnedPort(t *testing.T, sw *L2Switch, suffix byte, port PortID, want bool) {
	t.Helper()
	sw.mu.Lock()
	defer sw.mu.Unlock()
	entry := sw.fdb[fdbKey{mac: [6]byte{2, 0, 0, 0, 0, suffix}}]
	got := entry != nil && entry.port == port
	if got != want {
		t.Fatalf("FDB MAC suffix %d on port %d: got present=%t, want %t", suffix, port, got, want)
	}
}

func TestLegacySTPConfigurationBPDUParsingElectionAndTimers(t *testing.T) {
	base := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	sw := NewL2Switch(L2SwitchConfig{RSTPEnabled: true, BridgePriority: 32768, BridgeMAC: [6]byte{2, 0, 0, 0, 0, 2}, Ports: []L2PortConfig{{ID: 1, RSTPParticipant: true}, {ID: 2, RSTPParticipant: true}, {ID: 3}}})
	legacy := makeSTPConfigBPDU(RSTPBridgeID{Priority: 4096, MAC: [6]byte{2, 0, 0, 0, 0, 1}}, 4096, 1, 0)
	parsed, err := parseRSTPBPDU(legacy)
	if err != nil || !parsed.legacy || parsed.tcn || parsed.root.Priority != 4096 || parsed.forward != 15*time.Second {
		t.Fatalf("legacy config parse = %+v, %v", parsed, err)
	}
	if verdict := sw.Forward(1, legacy, base); verdict.Drop != L2Forward {
		t.Fatalf("legacy BPDU should be consumed, got %s", verdict.Drop)
	}
	role, state := sw.RSTPPortState(1)
	if role != RSTPRoleRoot || state != RSTPStateDiscarding {
		t.Fatalf("legacy superior BPDU selected %s/%s", role, state)
	}
	// Legacy bridges refresh configuration information every hello interval;
	// keep the superior root information alive through both forward delays.
	if verdict := sw.Forward(1, legacy, base.Add(15*time.Second)); verdict.Drop != L2Forward {
		t.Fatalf("legacy BPDU refresh should be consumed, got %s", verdict.Drop)
	}
	if got := sw.Forward(1, testRSTPDataFrame(), base.Add(15*time.Second)); got.Drop != L2DropRSTP {
		t.Fatalf("legacy root port should still be learning at first delay, drop=%s", got.Drop)
	}
	role, state = sw.RSTPPortState(1)
	if role != RSTPRoleRoot || state != RSTPStateLearning {
		t.Fatalf("after one legacy forward delay got %s/%s", role, state)
	}
	if got := sw.Forward(1, testRSTPDataFrame(), base.Add(30*time.Second)); got.Drop != L2Forward {
		t.Fatalf("legacy root port should forward after two delays, drop=%s", got.Drop)
	}
}

func TestLegacySTPDesignatedConfigTCNAndRootwardNotification(t *testing.T) {
	now := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	root := NewL2Switch(L2SwitchConfig{RSTPEnabled: true, BridgePriority: 4096, BridgeMAC: [6]byte{2, 0, 0, 0, 0, 2}, Ports: []L2PortConfig{{ID: 1, RSTPParticipant: true}, {ID: 2, RSTPParticipant: true}}})
	root.DueRSTPBPDUs(now) // Start each port's initial SEND_NEW migration timer.
	// Inferior 802.1D configuration information makes this bridge designated
	// on the segment and selects version-0 BPDU output there.
	inferior := makeSTPConfigBPDU(RSTPBridgeID{Priority: 8192, MAC: [6]byte{2, 0, 0, 0, 0, 3}}, 8192, 1, 0)
	root.Forward(1, inferior, now.Add(3100*time.Millisecond))
	root.Forward(2, inferior, now.Add(3100*time.Millisecond))
	out := root.DueRSTPBPDUs(now.Add(3100 * time.Millisecond))[1]
	parsed, err := parseRSTPBPDU(out)
	if err != nil || !parsed.legacy || parsed.tcn || parsed.root.Priority != 4096 || len(out) < 60 {
		t.Fatalf("designated output should be a v0 configuration BPDU: %+v %v", parsed, err)
	}
	root.Forward(1, makeSTPTCNBPDU(), now.Add(3200*time.Millisecond))
	rootBPDUs := root.DueRSTPBPDUs(now.Add(3200 * time.Millisecond))
	out = rootBPDUs[1]
	parsed, err = parseRSTPBPDU(out)
	if err != nil || !parsed.legacy || parsed.flags&stpFlagTCA == 0 || parsed.flags&rstpFlagTC == 0 || len(out) < 60 {
		t.Fatalf("TCN should be acknowledged and propagated in config BPDU: %+v %v", parsed, err)
	}
	rootsPeriodic := root.DueRSTPBPDUs(now.Add(5200 * time.Millisecond))
	propagated, err := parseRSTPBPDU(rootsPeriodic[2])
	if err != nil || !propagated.legacy || propagated.flags&rstpFlagTC == 0 || propagated.flags&stpFlagTCA != 0 || len(rootsPeriodic[2]) < 60 {
		t.Fatalf("root must propagate TC on other designated ports in padded v0 config BPDUs: %+v %v", propagated, err)
	}

	// A non-root bridge acknowledges the downstream TCN and emits a legacy
	// TCN on its root port until the root acknowledges it.
	transit := NewL2Switch(L2SwitchConfig{RSTPEnabled: true, BridgePriority: 32768, BridgeMAC: [6]byte{2, 0, 0, 0, 0, 4}, Ports: []L2PortConfig{{ID: 1, RSTPParticipant: true}, {ID: 2, RSTPParticipant: true}}})
	transit.DueRSTPBPDUs(now)
	superior := makeSTPConfigBPDU(RSTPBridgeID{Priority: 4096, MAC: [6]byte{2, 0, 0, 0, 0, 1}}, 4096, 1, 0)
	transit.Forward(1, superior, now.Add(3100*time.Millisecond))
	transit.Forward(2, makeSTPTCNBPDU(), now.Add(3200*time.Millisecond))
	bpdus := transit.DueRSTPBPDUs(now.Add(3300 * time.Millisecond))
	tcn, err := parseRSTPBPDU(bpdus[1])
	if err != nil || !tcn.legacy || !tcn.tcn || len(bpdus[1]) < 60 {
		t.Fatalf("non-root bridge should send v0 TCN toward root: %+v %v", tcn, err)
	}
	ack, err := parseRSTPBPDU(bpdus[2])
	if err != nil || !ack.legacy || ack.flags&stpFlagTCA == 0 || len(bpdus[2]) < 60 {
		t.Fatalf("designated downstream port should send TCA: %+v %v", ack, err)
	}
}

func TestLegacyMigrationWaitsForMigrateTimeBeforeReturningToRSTP(t *testing.T) {
	base := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	sw := NewL2Switch(L2SwitchConfig{RSTPEnabled: true, BridgePriority: 4096, BridgeMAC: [6]byte{2, 0, 0, 0, 0, 2}, Ports: []L2PortConfig{{ID: 1, RSTPParticipant: true}}})
	if first := sw.DueRSTPBPDUs(base)[1]; len(first) < 60 || first[19] != rstpVersion {
		t.Fatalf("new port should initially send padded RSTP, len=%d version=%d", len(first), first[19])
	}
	legacy := makeSTPConfigBPDU(RSTPBridgeID{Priority: 8192, MAC: [6]byte{2, 0, 0, 0, 0, 9}}, 8192, 1, 0)
	sw.Forward(1, legacy, base.Add(time.Second)) // Old BPDU during initial SEND_NEW window.
	rstpPeer := NewL2Switch(L2SwitchConfig{RSTPEnabled: true, BridgePriority: 8192, BridgeMAC: [6]byte{2, 0, 0, 0, 0, 9}, Ports: []L2PortConfig{{ID: 1, RSTPParticipant: true}}})
	rstpBPDU := rstpPeer.DueRSTPBPDUs(base.Add(time.Second))[1]
	sw.Forward(1, rstpBPDU, base.Add(2*time.Second))
	stillRSTP := sw.DueRSTPBPDUs(base.Add(2100 * time.Millisecond))[1]
	parsed, err := parseRSTPBPDU(stillRSTP)
	if err != nil || parsed.legacy {
		t.Fatalf("old BPDU during initial MigrateTime changed output from RSTP: %+v %v", parsed, err)
	}
	sw.Forward(1, legacy, base.Add(3100*time.Millisecond)) // First old BPDU after initial window.
	selectedLegacy := sw.DueRSTPBPDUs(base.Add(4200 * time.Millisecond))[1]
	parsed, err = parseRSTPBPDU(selectedLegacy)
	if err != nil || !parsed.legacy {
		t.Fatalf("old BPDU after initial MigrateTime should select legacy: %+v %v", parsed, err)
	}
	sw.Forward(1, rstpBPDU, base.Add(5*time.Second)) // New BPDU inside post-legacy lock.
	sw.Forward(1, makeSTPTCNBPDU(), base.Add(5100*time.Millisecond))
	stillLegacy := sw.DueRSTPBPDUs(base.Add(5200 * time.Millisecond))[1]
	parsed, err = parseRSTPBPDU(stillLegacy)
	if err != nil || !parsed.legacy {
		t.Fatalf("RSTP BPDU inside post-legacy lock changed output: %+v %v", parsed, err)
	}
	sw.Forward(1, rstpBPDU, base.Add(6200*time.Millisecond)) // First new BPDU after lock expiry.
	sw.DueRSTPBPDUs(base.Add(6300 * time.Millisecond))       // Snapshot follows the post-lock BPDU monotonically.
	sw.mu.Lock()
	legacyMode := sw.rstp.ports[1].legacy
	sw.mu.Unlock()
	if legacyMode {
		t.Fatal("post-lock RSTP BPDU did not restore RSTP transmit mode")
	}
	returned := sw.DueRSTPBPDUs(base.Add(7300 * time.Millisecond))[1]
	parsed, err = parseRSTPBPDU(returned)
	if err != nil || parsed.legacy {
		t.Fatalf("RSTP BPDU after sensing interval should restore RSTP output: %+v %v", parsed, err)
	}
}

func makeSTPConfigBPDU(root RSTPBridgeID, cost uint32, port uint16, flags byte) []byte {
	frame := make([]byte, EthHeaderLen+rstpLLCLength+stpConfigLength)
	copy(frame[:6], []byte{1, 0x80, 0xc2, 0, 0, 0})
	copy(frame[6:12], []byte{2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(frame[12:14], rstpLLCLength+stpConfigLength)
	frame[14], frame[15], frame[16] = 0x42, 0x42, 0x03
	body := frame[17:]
	binary.BigEndian.PutUint16(body[0:2], rstpProtocolID)
	body[2], body[3], body[4] = stpVersion, stpConfigBPDUType, flags
	encodeRSTPBridgeID(body[5:13], root)
	binary.BigEndian.PutUint32(body[13:17], cost)
	encodeRSTPBridgeID(body[17:25], RSTPBridgeID{Priority: root.Priority, MAC: [6]byte{2, 0, 0, 0, 0, 9}})
	binary.BigEndian.PutUint16(body[25:27], port)
	putRSTPTimer(body[27:29], 0)
	putRSTPTimer(body[29:31], 20*time.Second)
	putRSTPTimer(body[31:33], 2*time.Second)
	putRSTPTimer(body[33:35], 15*time.Second)
	return frame
}

func makeSTPTCNBPDU() []byte {
	frame := make([]byte, EthHeaderLen+rstpLLCLength+stpTCNLength)
	copy(frame[:6], []byte{1, 0x80, 0xc2, 0, 0, 0})
	copy(frame[6:12], []byte{2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(frame[12:14], rstpLLCLength+stpTCNLength)
	frame[14], frame[15], frame[16] = 0x42, 0x42, 0x03
	frame[17], frame[18], frame[19], frame[20] = 0, 0, stpVersion, stpTCNBPDUType
	return frame
}

func testRSTPDataFrame() []byte {
	return []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 9, 0x08, 0x06, 0, 1}
}
