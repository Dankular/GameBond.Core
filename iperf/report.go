// Package iperf parses and normalizes iperf3 JSON into a stable, unit-explicit
// report suitable for dashboards, automation and LLM analysis.
package iperf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const SchemaVersion = "gamebond.iperf.v1"
const maxJSONBytes = 2 << 20

// EndpointContext associates a measurement with the GameBond topology that
// carried it. Values are metadata only and are never inferred from iperf.
type EndpointContext struct {
	ClientID    string `json:"client_id,omitempty"`
	ExitID      string `json:"exit_id,omitempty"`
	GatewayID   string `json:"gateway_id,omitempty"`
	TopologyID  string `json:"topology_id,omitempty"`
	SegmentID   string `json:"segment_id,omitempty"`
	GatewayMode string `json:"gateway_mode,omitempty"`
}

// Report is the normalized result of one completed iperf run. Rates use
// decimal megabits per second (1 Mbps = 1,000,000 bits/s); byte counts are
// application payload bytes reported by iperf.
type Report struct {
	SchemaVersion string          `json:"schema_version"`
	Tool          string          `json:"tool"`
	State         string          `json:"state"`
	Protocol      string          `json:"protocol"`
	Direction     string          `json:"direction"`
	DurationSec   float64         `json:"duration_s"`
	Streams       int             `json:"streams"`
	Endpoint      EndpointContext `json:"endpoint"`
	Summary       Summary         `json:"summary"`
	Intervals     []Interval      `json:"intervals,omitempty"`
	Caveats       []string        `json:"caveats"`
	Error         string          `json:"error,omitempty"`
}

type Summary struct {
	SenderBytes     uint64  `json:"sender_bytes"`
	ReceiverBytes   uint64  `json:"receiver_bytes"`
	SenderMbps      float64 `json:"sender_mbps"`
	ReceiverMbps    float64 `json:"receiver_mbps"`
	TCPRetransmits  uint64  `json:"tcp_retransmits"`
	UDPLostPackets  uint64  `json:"udp_lost_packets"`
	UDPTotalPackets uint64  `json:"udp_total_packets"`
	UDPLossPct      float64 `json:"udp_loss_pct"`
	UDPJitterMS     float64 `json:"udp_jitter_ms"`
}

type Interval struct {
	StartSec       float64 `json:"start_s"`
	EndSec         float64 `json:"end_s"`
	DurationSec    float64 `json:"duration_s"`
	SenderBytes    uint64  `json:"sender_bytes"`
	ReceiverBytes  uint64  `json:"receiver_bytes"`
	SenderMbps     float64 `json:"sender_mbps"`
	ReceiverMbps   float64 `json:"receiver_mbps"`
	TCPRetransmits uint64  `json:"tcp_retransmits"`
	UDPLostPackets uint64  `json:"udp_lost_packets"`
	UDPLossPct     float64 `json:"udp_loss_pct"`
	UDPJitterMS    float64 `json:"udp_jitter_ms"`
}

type rawIperf struct {
	Start struct {
		TestStart struct {
			Protocol   string  `json:"protocol"`
			Reverse    int     `json:"reverse"`
			NumStreams int     `json:"num_streams"`
			Duration   float64 `json:"duration"`
		} `json:"test_start"`
	} `json:"start"`
	Intervals []struct {
		Sum        *rawSummary `json:"sum"`
		SumSent    *rawSummary `json:"sum_sent"`
		SumReceive *rawSummary `json:"sum_received"`
	} `json:"intervals"`
	End struct {
		SumSent    *rawSummary `json:"sum_sent"`
		SumReceive *rawSummary `json:"sum_received"`
		Sum        *rawSummary `json:"sum"`
	} `json:"end"`
	Error string `json:"error"`
}

type rawSummary struct {
	Start         float64 `json:"start"`
	End           float64 `json:"end"`
	Seconds       float64 `json:"seconds"`
	Bytes         uint64  `json:"bytes"`
	BitsPerSecond float64 `json:"bits_per_second"`
	Retransmits   uint64  `json:"retransmits"`
	LostPackets   uint64  `json:"lost_packets"`
	Packets       uint64  `json:"packets"`
	LostPercent   float64 `json:"lost_percent"`
	JitterMS      float64 `json:"jitter_ms"`
}

// ParseIperf3JSON parses client or server JSON emitted by iperf3-compatible
// tools such as iperf3-go. It preserves explicit units and adds topology tags.
func ParseIperf3JSON(data []byte, endpoint EndpointContext) (Report, error) {
	if len(data) == 0 || len(data) > maxJSONBytes {
		return Report{}, errors.New("iperf JSON is empty or exceeds the 2 MiB limit")
	}
	var raw rawIperf
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&raw); err != nil {
		return Report{}, fmt.Errorf("parse iperf JSON: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Report{}, errors.New("iperf JSON contains trailing data")
	}
	if raw.Error != "" {
		return Report{SchemaVersion: SchemaVersion, Tool: "iperf3", State: "failed", Endpoint: endpoint,
			Caveats: caveats(), Error: raw.Error}, errors.New(raw.Error)
	}
	protocol := strings.ToLower(raw.Start.TestStart.Protocol)
	if protocol == "" {
		return Report{}, errors.New("iperf JSON has no start.test_start.protocol")
	}
	direction := "client_to_server"
	if raw.Start.TestStart.Reverse != 0 {
		direction = "server_to_client"
	}
	r := Report{SchemaVersion: SchemaVersion, Tool: "iperf3", State: "complete", Protocol: protocol,
		Direction: direction, DurationSec: raw.Start.TestStart.Duration, Streams: raw.Start.TestStart.NumStreams,
		Endpoint: endpoint, Intervals: make([]Interval, 0, min(len(raw.Intervals), 1200)), Caveats: caveats()}
	if len(raw.Intervals) > 1200 {
		return Report{}, errors.New("iperf JSON contains more than 1200 interval samples")
	}
	for _, sample := range raw.Intervals {
		sent, received := sample.SumSent, sample.SumReceive
		if sample.Sum != nil {
			if sent == nil {
				sent = sample.Sum
			}
			if received == nil {
				received = sample.Sum
			}
		}
		interval := normalizeInterval(sent, received)
		r.Intervals = append(r.Intervals, interval)
	}
	sent, received := raw.End.SumSent, raw.End.SumReceive
	if raw.End.Sum != nil {
		if sent == nil {
			sent = raw.End.Sum
		}
		if received == nil {
			received = raw.End.Sum
		}
	}
	if sent != nil {
		r.Summary.SenderBytes = sent.Bytes
		r.Summary.SenderMbps = sent.BitsPerSecond / 1_000_000
		r.Summary.TCPRetransmits = sent.Retransmits
	}
	if received != nil {
		r.Summary.ReceiverBytes = received.Bytes
		r.Summary.ReceiverMbps = received.BitsPerSecond / 1_000_000
		r.Summary.UDPLostPackets = received.LostPackets
		r.Summary.UDPTotalPackets = received.Packets
		r.Summary.UDPLossPct = received.LostPercent
		r.Summary.UDPJitterMS = received.JitterMS
	}
	if r.Summary.UDPLostPackets == 0 && sent != nil {
		r.Summary.UDPLostPackets = sent.LostPackets
		r.Summary.UDPTotalPackets = sent.Packets
		r.Summary.UDPLossPct = sent.LostPercent
		r.Summary.UDPJitterMS = sent.JitterMS
	}
	return r, nil
}

// ClientOptions defines a bounded, on-demand iperf3-compatible client run.
// Executable may point to iperf3 or an iperf3-compatible implementation.
type ClientOptions struct {
	Executable string
	Target     string
	Port       int
	Duration   time.Duration
	Streams    int
	Protocol   string
	Reverse    bool
	Bandwidth  string
	Endpoint   EndpointContext
}

// RunClient executes one benchmark and returns only normalized JSON-ready
// stats. Raw tool output is bounded and never included in the report.
func RunClient(ctx context.Context, options ClientOptions) (Report, error) {
	if options.Executable == "" {
		options.Executable = "iperf3"
	}
	if options.Target == "" {
		return Report{}, errors.New("iperf target is required")
	}
	if options.Port == 0 {
		options.Port = 5201
	}
	if options.Port < 1 || options.Port > 65535 {
		return Report{}, errors.New("iperf port must be 1..65535")
	}
	if options.Duration == 0 {
		options.Duration = 10 * time.Second
	}
	if options.Duration < time.Second || options.Duration > 2*time.Minute {
		return Report{}, errors.New("iperf duration must be 1s..2m")
	}
	if options.Streams == 0 {
		options.Streams = 1
	}
	if options.Streams < 1 || options.Streams > 16 {
		return Report{}, errors.New("iperf streams must be 1..16")
	}
	protocol := strings.ToLower(options.Protocol)
	if protocol == "" {
		protocol = "tcp"
	}
	if protocol != "tcp" && protocol != "udp" {
		return Report{}, errors.New("iperf protocol must be tcp or udp")
	}
	seconds := strconv.FormatFloat(options.Duration.Seconds(), 'f', 0, 64)
	args := []string{"-c", options.Target, "-p", strconv.Itoa(options.Port), "-t", seconds, "-P", strconv.Itoa(options.Streams), "-J"}
	if protocol == "udp" {
		args = append(args, "-u")
	}
	if options.Bandwidth != "" {
		if protocol != "udp" {
			return Report{}, errors.New("iperf bandwidth limit applies to UDP runs only")
		}
		args = append(args, "-b", options.Bandwidth)
	}
	if options.Reverse {
		args = append(args, "-R")
	}
	cmd := exec.CommandContext(ctx, options.Executable, args...)
	var stdout limitedBuffer
	var stderr limitedBuffer
	stdout.limit, stderr.limit = maxJSONBytes, 16<<10
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return Report{}, ctx.Err()
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return Report{SchemaVersion: SchemaVersion, Tool: "iperf3", State: "failed", Protocol: protocol, Endpoint: options.Endpoint, Caveats: caveats(), Error: msg}, fmt.Errorf("run iperf client: %s", msg)
	}
	report, err := ParseIperf3JSON(stdout.Bytes(), options.Endpoint)
	if err != nil {
		return report, err
	}
	report.Tool = options.Executable
	return report, nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - b.Len()
	if remaining > 0 {
		_, _ = b.Buffer.Write(p[:min(len(p), remaining)])
	}
	return n, nil
}

func normalizeInterval(sent, received *rawSummary) Interval {
	var out Interval
	if sent != nil {
		out.StartSec, out.EndSec = sent.Start, sent.End
		out.DurationSec = sent.Seconds
		out.SenderBytes = sent.Bytes
		out.SenderMbps = sent.BitsPerSecond / 1_000_000
		out.TCPRetransmits = sent.Retransmits
	}
	if received != nil {
		if out.EndSec == 0 {
			out.StartSec, out.EndSec = received.Start, received.End
		}
		if out.DurationSec == 0 {
			out.DurationSec = received.Seconds
		}
		out.ReceiverBytes = received.Bytes
		out.ReceiverMbps = received.BitsPerSecond / 1_000_000
		out.UDPLostPackets = received.LostPackets
		out.UDPLossPct = received.LostPercent
		out.UDPJitterMS = received.JitterMS
	}
	return out
}

func caveats() []string {
	return []string{
		"iperf measures application-layer throughput between its endpoints; it is not a raw link-capacity measurement",
		"GameBond path health, tunnel overhead, and the measured endpoint route should be interpreted alongside this report",
	}
}
