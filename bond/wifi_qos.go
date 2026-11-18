package bond

// DiffservToWiFiUP maps a six-bit DSCP to the recommended IEEE 802.11 User
// Priority from RFC 8325, Figure 1. Unlisted codepoints map to best effort
// (UP 0). CS6 and CS7 also map to best effort here because RFC 8325 cautions
// that UP 7 / AC_VO must only be used for trusted network-control traffic.
// ECN is not part of DSCP and must not be passed to this function.
func DiffservToWiFiUP(dscp byte) byte {
	if dscp > 63 {
		return 0
	}
	switch {
	case dscp == 8: // CS1, Low-Priority Data
		return 1
	case dscp == 24: // CS3, Broadcast Video
		return 4
	case dscp == 32: // CS4, Real-Time Interactive
		return 4
	case dscp == 40: // CS5, Signaling
		return 5
	case dscp == 46 || dscp == 44: // EF / VA, Telephony
		return 6
	case dscp >= 34 && dscp <= 38 && dscp%2 == 0: // AF4x, Multimedia Conferencing
		return 4
	case dscp >= 26 && dscp <= 30 && dscp%2 == 0: // AF3x, Multimedia Streaming
		return 4
	case dscp >= 18 && dscp <= 22 && dscp%2 == 0: // AF2x, Low-Latency Data
		return 3
	default:
		return 0
	}
}

// WiFiSafeDSCP applies RFC 8325's upstream client recommendation: preserve
// end-to-end DSCP markings for wired Diffserv treatment, while resetting CS6
// and CS7 because wireless endpoints must not originate network-control
// markings. The operating system may separately map DSCP to Wi-Fi UP.
func WiFiSafeDSCP(dscp byte) byte {
	if dscp == 48 || dscp == 56 { // CS6 / CS7
		return 0
	}
	return dscp
}
