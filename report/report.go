package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/HaizakiKu/quic-prober/compare"
	"github.com/HaizakiKu/quic-prober/probe"
)

const separator = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

func PrintHuman(comparisons []compare.Comparison) {
	if len(comparisons) == 0 {
		return
	}
	target := comparisons[0].Target.Target
	ref := comparisons[0].Reference.Target
	if ref == "" && len(comparisons[0].References) > 0 {
		ref = comparisons[0].References[0].Target
	}

	fmt.Println()
	fmt.Println("quic-prober v0.1.0")
	fmt.Println(separator)
	fmt.Printf("Target:    %s\n", target)
	fmt.Printf("Reference: %s\n", ref)
	fmt.Println(separator)
	fmt.Println()

	for _, c := range comparisons {
		icon := scoreIcon(c.Score)
		fmt.Printf("[%s %s] %s\n", icon, c.Score, probeName(c.ProbeName))
		for _, f := range c.Findings {
			fmt.Printf("  %s\n", f)
		}
		fmt.Println()
	}

	fmt.Println(separator)
	overall, passed, warned, failed := summarize(comparisons)
	fmt.Printf("Overall: %s %s\n", scoreIcon(overall), riskLabel(overall))
	fmt.Printf("  %d passed", passed)
	if warned > 0 {
		fmt.Printf(", %d warning(s)", warned)
	}
	if failed > 0 {
		fmt.Printf(", %d failure(s)", failed)
	}
	fmt.Println()
	fmt.Println(separator)
	fmt.Println()
}

func PrintVerboseResult(r probe.Result) {
	fmt.Printf("  [verbose] %s → %s\n", r.Target, r.ProbeName)
	fmt.Printf("    connected=%v gotAppData=%v status=%d alpn=%q\n",
		r.Connected, r.GotAppData, r.HTTPStatus, r.ALPN)
	if r.CloseErrorType != "" {
		fmt.Printf("    close: by=%s type=%s code=%d reason=%q\n",
			r.ClosedBy, r.CloseErrorType, r.CloseCode, r.CloseReason)
	}
	if r.Err != nil {
		fmt.Printf("    error: %v\n", r.Err)
	}
}

type jsonResult struct {
	ProbeName      string            `json:"probe_name"`
	Target         string            `json:"target"`
	Connected      bool              `json:"connected"`
	ConnectTimeMs  float64           `json:"connect_time_ms"`
	GotAppData     bool              `json:"got_app_data"`
	AppDataSize    int               `json:"app_data_size"`
	ResponseTimeMs float64           `json:"response_time_ms"`
	ClosedBy       string            `json:"closed_by,omitempty"`
	CloseErrorType string            `json:"close_error_type,omitempty"`
	CloseCode      uint64            `json:"close_code,omitempty"`
	CloseReason    string            `json:"close_reason,omitempty"`
	HTTPStatus     int               `json:"http_status,omitempty"`
	HTTPHeaders    map[string]string `json:"http_headers,omitempty"`
	TLSVersion     uint16            `json:"tls_version,omitempty"`
	CipherSuite    uint16            `json:"cipher_suite,omitempty"`
	ALPN           string            `json:"alpn,omitempty"`
	CertSubject    string            `json:"cert_subject,omitempty"`
	CertIssuer     string            `json:"cert_issuer,omitempty"`
	CertExpiry     string            `json:"cert_expiry,omitempty"`
	HasECH         bool              `json:"has_ech,omitempty"`
	RawResponse    []byte            `json:"raw_response,omitempty"`
	ErrMsg         string            `json:"error,omitempty"`
}

type jsonComparison struct {
	ProbeName string     `json:"probe_name"`
	Score     string     `json:"score"`
	Findings  []string   `json:"findings"`
	Target    jsonResult `json:"target"`
	Reference jsonResult `json:"reference"`
}

type jsonOutput struct {
	Version     string           `json:"version"`
	Comparisons []jsonComparison `json:"comparisons"`
}

func PrintJSON(comparisons []compare.Comparison) {
	out := jsonOutput{
		Version:     "0.1.0",
		Comparisons: make([]jsonComparison, len(comparisons)),
	}
	for i, c := range comparisons {
		out.Comparisons[i] = jsonComparison{
			ProbeName: c.ProbeName,
			Score:     c.Score.String(),
			Findings:  c.Findings,
			Target:    toJSONResult(c.Target),
			Reference: toJSONResult(c.Reference),
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

func toJSONResult(r probe.Result) jsonResult {
	j := jsonResult{
		ProbeName:      r.ProbeName,
		Target:         r.Target,
		Connected:      r.Connected,
		ConnectTimeMs:  r.ConnectTime.Seconds() * 1000,
		GotAppData:     r.GotAppData,
		AppDataSize:    r.AppDataSize,
		ResponseTimeMs: r.ResponseTime.Seconds() * 1000,
		ClosedBy:       r.ClosedBy,
		CloseErrorType: r.CloseErrorType,
		CloseCode:      r.CloseCode,
		CloseReason:    r.CloseReason,
		HTTPStatus:     r.HTTPStatus,
		HTTPHeaders:    r.HTTPHeaders,
		TLSVersion:     r.TLSVersion,
		CipherSuite:    r.CipherSuite,
		ALPN:           r.ALPN,
		CertSubject:    r.CertSubject,
		CertIssuer:     r.CertIssuer,
		CertExpiry:     r.CertExpiry,
		HasECH:         r.HasECH,
		RawResponse:    r.RawResponse,
	}
	if r.Err != nil {
		j.ErrMsg = r.Err.Error()
	}
	return j
}

func ExitCode(comparisons []compare.Comparison) int {
	worst := compare.ScorePass
	for _, c := range comparisons {
		if c.Score > worst {
			worst = c.Score
		}
	}
	switch worst {
	case compare.ScoreFail:
		return 2
	case compare.ScoreWarn:
		return 1
	default:
		return 0
	}
}

func summarize(comparisons []compare.Comparison) (overall compare.Score, passed, warned, failed int) {
	for _, c := range comparisons {
		switch c.Score {
		case compare.ScorePass:
			passed++
		case compare.ScoreWarn:
			warned++
		case compare.ScoreFail:
			failed++
		}
		if c.Score > overall {
			overall = c.Score
		}
	}
	return
}

func scoreIcon(s compare.Score) string {
	switch s {
	case compare.ScorePass:
		return "✅"
	case compare.ScoreWarn:
		return "⚠️ "
	case compare.ScoreFail:
		return "❌"
	default:
		return "?"
	}
}

func riskLabel(s compare.Score) string {
	switch s {
	case compare.ScorePass:
		return "LOW RISK"
	case compare.ScoreWarn:
		return "LOW-MEDIUM RISK"
	case compare.ScoreFail:
		return "HIGH RISK"
	default:
		return "UNKNOWN"
	}
}

func probeName(name string) string {
	switch name {
	case "http3":
		return "HTTP/3 GET /"
	case "tls":
		return "TLS Handshake"
	case "replay":
		return "Replay probe"
	case "null":
		return "Null connection"
	case "random":
		return "Random UDP"
	case "malformed":
		return "Malformed QUIC Initial"
	default:
		return name
	}
}
