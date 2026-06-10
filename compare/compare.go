package compare

import (
	"fmt"
	"math"
	"time"

	"github.com/HaizakiKu/quic-prober/probe"
	"github.com/HaizakiKu/quic-prober/samples"
)

type Score int

const (
	ScorePass Score = iota
	ScoreWarn
	ScoreFail
)

func (s Score) String() string {
	switch s {
	case ScorePass:
		return "PASS"
	case ScoreWarn:
		return "WARN"
	case ScoreFail:
		return "FAIL"
	default:
		return "UNKNOWN"
	}
}

type ReferenceMode string

const (
	ReferenceModeAny      ReferenceMode = "any"
	ReferenceModeMajority ReferenceMode = "majority"
	ReferenceModeAll      ReferenceMode = "all"
)

type Comparison struct {
	ProbeName  string
	Target     probe.Result
	Reference  probe.Result
	References []probe.Result
	Score      Score
	Findings   []string
}

func Compare(target probe.Result, refs []probe.Result, mode ReferenceMode) Comparison {
	ref := mergeReferences(refs, mode)
	c := Comparison{
		ProbeName:  target.ProbeName,
		Target:     target,
		Reference:  ref,
		References: refs,
	}
	c.Score, c.Findings = scoreProbe(target, ref)
	return c
}

func mergeReferences(refs []probe.Result, mode ReferenceMode) probe.Result {
	if len(refs) == 0 {
		return probe.Result{}
	}
	if len(refs) == 1 {
		return refs[0]
	}

	merged := probe.Result{
		ProbeName: refs[0].ProbeName,
	}

	merged.Connected = mergeBool(boolSlice(refs, func(r probe.Result) bool { return r.Connected }), mode)
	merged.GotAppData = mergeBool(boolSlice(refs, func(r probe.Result) bool { return r.GotAppData }), mode)
	merged.HasECH = mergeBool(boolSlice(refs, func(r probe.Result) bool { return r.HasECH }), mode)

	merged.ALPN = majorityString(stringSlice(refs, func(r probe.Result) string { return r.ALPN }))
	merged.CloseErrorType = majorityString(stringSlice(refs, func(r probe.Result) string { return r.CloseErrorType }))
	merged.ClosedBy = majorityString(stringSlice(refs, func(r probe.Result) string { return r.ClosedBy }))

	merged.HTTPStatus = majorityInt(intSlice(refs, func(r probe.Result) int { return r.HTTPStatus }))
	merged.CloseCode = majorityUint64(uint64Slice(refs, func(r probe.Result) uint64 { return r.CloseCode }))
	merged.TLSVersion = majorityUint16(uint16Slice(refs, func(r probe.Result) uint16 { return r.TLSVersion }))
	merged.CipherSuite = majorityUint16(uint16Slice(refs, func(r probe.Result) uint16 { return r.CipherSuite }))

	var totalConnect, totalResponse int64
	for _, r := range refs {
		totalConnect += r.ConnectTime.Nanoseconds()
		totalResponse += r.ResponseTime.Nanoseconds()
	}
	merged.ConnectTime = time.Duration(totalConnect / int64(len(refs)))
	merged.ResponseTime = time.Duration(totalResponse / int64(len(refs)))

	return merged
}

func scoreProbe(target, ref probe.Result) (Score, []string) {
	switch target.ProbeName {
	case "http3":
		return scoreHTTP3(target, ref)
	case "tls":
		return scoreTLS(target, ref)
	case "replay":
		return scoreReplay(target, ref)
	case "null":
		return scoreNull(target, ref)
	case "random":
		return scoreRandom(target, ref)
	case "malformed":
		return scoreMalformed(target, ref)
	default:
		return ScorePass, nil
	}
}

func scoreHTTP3(target, ref probe.Result) (Score, []string) {
	var findings []string

	if !target.Connected {
		findings = append(findings, "Failed to connect — server may not support QUIC/HTTP3")
		return ScoreFail, findings
	}
	if target.HTTPStatus != 200 {
		findings = append(findings, fmt.Sprintf("HTTP status %d (expected 200) — configure masquerade web server", target.HTTPStatus))
		return ScoreFail, findings
	}

	score := ScorePass
	if target.HTTPHeaders["Server"] == "" {
		findings = append(findings, "Missing \"Server\" header → configure masquerade reverse proxy to add Server header")
		score = ScoreWarn
	}

	timeDiff := math.Abs(float64(target.ResponseTime) - float64(ref.ResponseTime))
	if timeDiff > 500e6 { // 500ms in nanoseconds
		findings = append(findings, fmt.Sprintf("Response time diff %.0fms exceeds 500ms threshold", timeDiff/1e6))
		if score < ScoreWarn {
			score = ScoreWarn
		}
	}

	if score == ScorePass {
		findings = append(findings, fmt.Sprintf("Status 200 OK, Server: %q, response time within threshold", target.HTTPHeaders["Server"]))
	}
	return score, findings
}

func scoreTLS(target, ref probe.Result) (Score, []string) {
	var findings []string

	if !target.Connected {
		findings = append(findings, "TLS handshake failed — server may not support QUIC")
		return ScoreFail, findings
	}

	if target.ALPN != "h3" {
		findings = append(findings, fmt.Sprintf("ALPN negotiated %q instead of \"h3\" — server not advertising h3", target.ALPN))
		return ScoreFail, findings
	}

	score := ScorePass
	if target.CertSubject != "" && target.CertIssuer != "" && target.CertSubject == target.CertIssuer {
		findings = append(findings, "Certificate is self-signed (Issuer == Subject) — GFW-detectable, use CA-signed cert")
		score = ScoreWarn
	}

	if ref.CipherSuite != 0 && target.CipherSuite != ref.CipherSuite {
		findings = append(findings, fmt.Sprintf("Cipher suite 0x%04x differs from reference 0x%04x", target.CipherSuite, ref.CipherSuite))
		if score < ScoreWarn {
			score = ScoreWarn
		}
	}

	if score == ScorePass {
		findings = append(findings, fmt.Sprintf("ALPN h3 ✓, cipher 0x%04x ✓, cert: %s", target.CipherSuite, target.CertSubject))
	}
	return score, findings
}

func scoreReplay(target, ref probe.Result) (Score, []string) {
	var findings []string

	targetIsVN := len(target.RawResponse) > 0 && samples.IsVersionNegotiation(target.RawResponse)
	refIsVN := len(ref.RawResponse) > 0 && samples.IsVersionNegotiation(ref.RawResponse)

	if target.GotAppData && !targetIsVN {
		findings = append(findings, "Server accepted replayed QUIC Initial — no replay protection")
		return ScoreFail, findings
	}

	targetClass := classifyReplayResponse(target.GotAppData, targetIsVN)
	refClass := classifyReplayResponse(ref.GotAppData, refIsVN)

	if targetClass != refClass {
		findings = append(findings, fmt.Sprintf("Response pattern differs: target=%s, reference=%s", targetClass, refClass))
		return ScoreWarn, findings
	}

	if target.CloseErrorType != ref.CloseErrorType || target.CloseCode != ref.CloseCode {
		findings = append(findings, fmt.Sprintf("Close behavior differs: target=%s/%d, reference=%s/%d",
			target.CloseErrorType, target.CloseCode, ref.CloseErrorType, ref.CloseCode))
		return ScoreWarn, findings
	}

	findings = append(findings, fmt.Sprintf("Both servers: %s ✓", targetClass))
	return ScorePass, findings
}

func classifyReplayResponse(gotData, isVN bool) string {
	if !gotData {
		return "no-response"
	}
	if isVN {
		return "version-negotiation"
	}
	return "app-data"
}

func scoreNull(target, ref probe.Result) (Score, []string) {
	var findings []string

	if !target.Connected {
		findings = append(findings, "Failed to connect for null probe")
		return ScoreFail, findings
	}

	if target.GotAppData {
		findings = append(findings, "Server pushed HTTP/3 stream unprompted — active probing signature")
		return ScoreFail, findings
	}

	if target.CloseErrorType != ref.CloseErrorType || target.CloseCode != ref.CloseCode {
		findings = append(findings, fmt.Sprintf("Close behavior differs: target=%s/%d, reference=%s/%d",
			target.CloseErrorType, target.CloseCode, ref.CloseErrorType, ref.CloseCode))
		return ScoreWarn, findings
	}

	findings = append(findings, "No unprompted streams, idle timeout matches reference ✓")
	return ScorePass, findings
}

func scoreRandom(target, ref probe.Result) (Score, []string) {
	var findings []string

	if target.GotAppData {
		findings = append(findings, fmt.Sprintf("Server responded to random UDP (%d bytes) — unexpected behavior", target.AppDataSize))
		return ScoreFail, findings
	}

	findings = append(findings, "No response to random UDP ✓")
	return ScorePass, findings
}

func scoreMalformed(target, ref probe.Result) (Score, []string) {
	var findings []string

	if target.GotAppData {
		findings = append(findings, "Server returned application data for malformed packet — reveals internal state")
		return ScoreFail, findings
	}

	targetHasResp := target.GotAppData || len(target.RawResponse) > 0
	refHasResp := ref.GotAppData || len(ref.RawResponse) > 0

	if targetHasResp != refHasResp {
		findings = append(findings, "Response pattern for malformed packets differs from reference")
		return ScoreWarn, findings
	}

	findings = append(findings, "All malformed variants: no application data returned ✓")
	return ScorePass, findings
}

func boolSlice(refs []probe.Result, fn func(probe.Result) bool) []bool {
	out := make([]bool, len(refs))
	for i, r := range refs {
		out[i] = fn(r)
	}
	return out
}

func stringSlice(refs []probe.Result, fn func(probe.Result) string) []string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = fn(r)
	}
	return out
}

func intSlice(refs []probe.Result, fn func(probe.Result) int) []int {
	out := make([]int, len(refs))
	for i, r := range refs {
		out[i] = fn(r)
	}
	return out
}

func uint64Slice(refs []probe.Result, fn func(probe.Result) uint64) []uint64 {
	out := make([]uint64, len(refs))
	for i, r := range refs {
		out[i] = fn(r)
	}
	return out
}

func uint16Slice(refs []probe.Result, fn func(probe.Result) uint16) []uint16 {
	out := make([]uint16, len(refs))
	for i, r := range refs {
		out[i] = fn(r)
	}
	return out
}

func mergeBool(vals []bool, mode ReferenceMode) bool {
	trueCount := 0
	for _, v := range vals {
		if v {
			trueCount++
		}
	}
	switch mode {
	case ReferenceModeAny:
		return trueCount > 0
	case ReferenceModeAll:
		return trueCount == len(vals)
	default: // majority
		return trueCount > len(vals)/2
	}
}

func majorityString(vals []string) string {
	count := make(map[string]int)
	for _, v := range vals {
		count[v]++
	}
	best, max := "", 0
	for v, c := range count {
		if c > max {
			best, max = v, c
		}
	}
	return best
}

func majorityInt(vals []int) int {
	count := make(map[int]int)
	for _, v := range vals {
		count[v]++
	}
	best, max := 0, 0
	for v, c := range count {
		if c > max {
			best, max = v, c
		}
	}
	return best
}

func majorityUint64(vals []uint64) uint64 {
	count := make(map[uint64]int)
	for _, v := range vals {
		count[v]++
	}
	var best uint64
	max := 0
	for v, c := range count {
		if c > max {
			best, max = v, c
		}
	}
	return best
}

func majorityUint16(vals []uint16) uint16 {
	count := make(map[uint16]int)
	for _, v := range vals {
		count[v]++
	}
	var best uint16
	max := 0
	for v, c := range count {
		if c > max {
			best, max = v, c
		}
	}
	return best
}
