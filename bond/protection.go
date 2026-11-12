package bond

// Redundancy is not configurable. With two or more ready paths every packet is sent on
// one path and copied onto another from the first packet on (see Sender.protectionLevel);
// the receiver keeps whichever copy arrives first. Reed-Solomon parity, SACK recovery and
// repairs sit on top of that for bursts that hit both paths. There are no presets.
