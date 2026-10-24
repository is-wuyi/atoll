package scheduler

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

const (
	TransferHTTP   = "http"
	TransferHTTPS  = "https"
	TransferDirect = "direct"
	TransferRelay  = "circuit"
)

type EndpointBandwidth struct {
	ID                  string `json:"id"`
	UploadBPS           uint64 `json:"upload_bps"`
	DownloadBPS         uint64 `json:"download_bps"`
	InFlightUploadBPS   uint64 `json:"in_flight_upload_bps"`
	InFlightDownloadBPS uint64 `json:"in_flight_download_bps"`
	MaxConcurrent       int    `json:"max_concurrent"`
}

type LinkObservation struct {
	From          string    `json:"from"`
	To            string    `json:"to"`
	Path          string    `json:"path"`
	Available     bool      `json:"available"`
	RTTMs         float64   `json:"rtt_ms"`
	ThroughputBPS uint64    `json:"throughput_bps"`
	Confidence    float64   `json:"confidence"`
	ObservedAt    time.Time `json:"observed_at"`
	ValidUntil    time.Time `json:"valid_until"`
}

type TransferNetwork struct {
	Origin           string              `json:"origin"`
	Endpoints        []EndpointBandwidth `json:"endpoints"`
	Links            []LinkObservation   `json:"links"`
	MaxUploadTargets int                 `json:"max_upload_targets"`
	MaxConcurrent    int                 `json:"max_concurrent"`
	PlanTTLSeconds   int                 `json:"plan_ttl_seconds"`
	MinConfidence    float64             `json:"min_confidence"`
	index            map[string]*LinkObservation
}

type TransferLeg struct {
	From string `json:"from"`
	To   string `json:"to"`
	Path string `json:"path"`
	BPS  uint64 `json:"bps"`
}

type WriteTransfer struct {
	UploadTargets    []string      `json:"upload_targets"`
	Legs             []TransferLeg `json:"legs"`
	ExpiresAt        time.Time     `json:"expires_at"`
	EstimatedSeconds float64       `json:"estimated_seconds"`
}

func validateTransferNetwork(n *TransferNetwork, now time.Time) error {
	if n == nil || now.IsZero() || n.Origin == "" || len(n.Origin) > 128 || len(n.Endpoints) == 0 || len(n.Endpoints) > 257 || len(n.Links) > 4096 || n.MaxUploadTargets < 1 || n.MaxUploadTargets > 4 || n.MaxConcurrent < 1 || n.MaxConcurrent > 32 || n.PlanTTLSeconds < 1 || n.PlanTTLSeconds > 3600 || !finiteNonNeg(n.MinConfidence) || n.MinConfidence > 1 {
		return errors.New("invalid transfer network limits")
	}
	seen := map[string]bool{}
	for _, e := range n.Endpoints {
		if e.ID == "" || len(e.ID) > 128 || seen[e.ID] || e.UploadBPS == 0 || e.DownloadBPS == 0 || e.InFlightUploadBPS > e.UploadBPS || e.InFlightDownloadBPS > e.DownloadBPS || e.MaxConcurrent < 1 || e.MaxConcurrent > 32 {
			return errors.New("invalid endpoint bandwidth budget")
		}
		seen[e.ID] = true
	}
	if !seen[n.Origin] {
		return errors.New("missing transfer origin budget")
	}
	pairs := map[string]bool{}
	for _, l := range n.Links {
		key := l.From + "\x00" + l.To + "\x00" + l.Path
		if !seen[l.From] || !seen[l.To] || l.From == l.To || pairs[key] || !transferPath(l.Path) || !finiteNonNeg(l.RTTMs) || !finiteNonNeg(l.Confidence) || l.Confidence > 1 || l.ObservedAt.IsZero() || !l.ValidUntil.After(l.ObservedAt) || l.ObservedAt.After(now.Add(time.Second)) || l.ValidUntil.Sub(l.ObservedAt) > time.Hour {
			return errors.New("invalid directional link observation")
		}
		pairs[key] = true
	}
	return nil
}

func transferPath(path string) bool {
	return path == TransferHTTP || path == TransferHTTPS || path == TransferDirect || path == TransferRelay
}

func availableBandwidth(e EndpointBandwidth) (uint64, uint64) {
	return e.UploadBPS - e.InFlightUploadBPS, e.DownloadBPS - e.InFlightDownloadBPS
}

func usableLink(n *TransferNetwork, from, to, path string, now time.Time) *LinkObservation {
	if n.index != nil {
		return n.index[from+"\x00"+to+"\x00"+path]
	}
	var best *LinkObservation
	for i := range n.Links {
		l := &n.Links[i]
		if l.From != from || l.To != to || path != "" && l.Path != path || !l.Available || l.Confidence < n.MinConfidence || !now.Before(l.ValidUntil) {
			continue
		}
		if best == nil || pathRank(l.Path) < pathRank(best.Path) || pathRank(l.Path) == pathRank(best.Path) && (l.ThroughputBPS > best.ThroughputBPS || l.ThroughputBPS == best.ThroughputBPS && (l.RTTMs < best.RTTMs || l.RTTMs == best.RTTMs && l.Path < best.Path)) {
			best = l
		}
	}
	return best
}

func indexTransferNetwork(n *TransferNetwork, now time.Time) {
	n.index = make(map[string]*LinkObservation, len(n.Links)*2)
	for i := range n.Links {
		link := &n.Links[i]
		if !link.Available || link.Confidence < n.MinConfidence || !now.Before(link.ValidUntil) {
			continue
		}
		key := link.From + "\x00" + link.To + "\x00"
		n.index[key+link.Path] = link
		best := n.index[key]
		if best == nil || pathRank(link.Path) < pathRank(best.Path) || pathRank(link.Path) == pathRank(best.Path) && (link.ThroughputBPS > best.ThroughputBPS || link.ThroughputBPS == best.ThroughputBPS && (link.RTTMs < best.RTTMs || link.RTTMs == best.RTTMs && link.Path < best.Path)) {
			n.index[key] = link
		}
	}
}

func pathRank(path string) int {
	if path == TransferRelay {
		return 1
	}
	return 0
}

func endpointIndex(n *TransferNetwork) map[string]EndpointBandwidth {
	out := make(map[string]EndpointBandwidth, len(n.Endpoints))
	for _, e := range n.Endpoints {
		out[e.ID] = e
	}
	return out
}

// Unknown goodput is bounded by configured budgets, not represented as a measurement.
func transferRate(link *LinkObservation, source, target EndpointBandwidth) uint64 {
	up, _ := availableBandwidth(source)
	_, down := availableBandwidth(target)
	rate := min(up, down)
	if link.ThroughputBPS != 0 {
		rate = min(rate, link.ThroughputBPS)
	}
	return rate
}

func planWriteTransfer(n *TransferNetwork, targets, confirms []string, size uint64, now time.Time) (*WriteTransfer, error) {
	if n.index == nil {
		if err := validateTransferNetwork(n, now); err != nil {
			return nil, err
		}
		copy := *n
		indexTransferNetwork(&copy, now)
		n = &copy
	}
	endpoints := endpointIndex(n)
	var ingress []string
	for _, id := range confirms {
		if id != n.Origin && usableLink(n, n.Origin, id, "", now) != nil {
			ingress = append(ingress, id)
		}
	}
	sort.Strings(ingress)
	var best *WriteTransfer
	budget := 128
	for count := 1; count <= min(n.MaxUploadTargets, len(ingress)) && budget > 0; count++ {
		sets := combinations(len(ingress), count, 32)
		if sets == nil {
			sets = make([][]int, 0, min(32, len(ingress)))
			for shift := 0; shift < min(32, len(ingress)); shift++ {
				set := make([]int, count)
				for i := range set {
					set[i] = (shift + i) % len(ingress)
				}
				sets = append(sets, set)
			}
		}
		for _, set := range sets {
			if budget == 0 {
				break
			}
			budget--
			p := &WriteTransfer{ExpiresAt: now.Add(time.Duration(n.PlanTTLSeconds) * time.Second)}
			for _, i := range set {
				id := ingress[i]
				p.UploadTargets = append(p.UploadTargets, id)
				l := usableLink(n, n.Origin, id, "", now)
				p.Legs = append(p.Legs, TransferLeg{From: n.Origin, To: id, Path: l.Path})
			}
			sort.Strings(p.UploadTargets)
			assigned := map[string]int{}
			valid := true
			ordered := append([]string(nil), targets...)
			sort.Strings(ordered)
			for _, id := range ordered {
				if stringMember(p.UploadTargets, id) {
					continue
				}
				var source string
				var selected *LinkObservation
				var score uint64
				for _, from := range p.UploadTargets {
					l := usableLink(n, from, id, "", now)
					if l == nil {
						continue
					}
					rate := transferRate(l, endpoints[from], endpoints[id]) / uint64(assigned[from]+1)
					if rate > score || rate != 0 && rate == score && from < source {
						source, selected, score = from, l, rate
					}
				}
				if selected == nil {
					valid = false
					break
				}
				assigned[source]++
				p.Legs = append(p.Legs, TransferLeg{From: source, To: id, Path: selected.Path})
			}
			if !valid || !allocateTransferRates(n, p, endpoints, now) {
				continue
			}
			p.EstimatedSeconds = transferDuration(n.Origin, p.Legs, size)
			if p.EstimatedSeconds > float64(n.PlanTTLSeconds) {
				continue
			}
			if best == nil || p.EstimatedSeconds < best.EstimatedSeconds || p.EstimatedSeconds == best.EstimatedSeconds && fmt.Sprint(p.UploadTargets, p.Legs) < fmt.Sprint(best.UploadTargets, best.Legs) {
				best = p
			}
		}
	}
	if best == nil {
		return nil, errors.New("no budgeted ingress and replica path reaches every target")
	}
	return best, nil
}

func allocateTransferRates(n *TransferNetwork, p *WriteTransfer, endpoints map[string]EndpointBandwidth, now time.Time) bool {
	out, in := map[string]int{}, map[string]int{}
	for _, l := range p.Legs {
		out[l.From]++
		in[l.To]++
	}
	for i := range p.Legs {
		leg := &p.Legs[i]
		from, to := endpoints[leg.From], endpoints[leg.To]
		if out[leg.From] > min(n.MaxConcurrent, from.MaxConcurrent) || in[leg.To] > min(n.MaxConcurrent, to.MaxConcurrent) {
			return false
		}
		up, _ := availableBandwidth(from)
		_, down := availableBandwidth(to)
		leg.BPS = min(up/uint64(max(out[leg.From], from.MaxConcurrent)), down/uint64(max(in[leg.To], to.MaxConcurrent)))
		if link := usableLink(n, leg.From, leg.To, leg.Path, now); link != nil && link.ThroughputBPS != 0 {
			leg.BPS = min(leg.BPS, link.ThroughputBPS)
		}
		if leg.BPS == 0 {
			return false
		}
	}
	return true
}

func transferDuration(origin string, legs []TransferLeg, size uint64) float64 {
	arrivals := map[string]float64{}
	for _, l := range legs {
		if l.From == origin {
			arrivals[l.To] = float64(size) / float64(l.BPS)
		}
	}
	longest := 0.0
	for _, l := range legs {
		seconds := float64(size) / float64(l.BPS)
		if l.From != origin {
			seconds += arrivals[l.From]
		}
		longest = math.Max(longest, seconds)
	}
	return longest
}

func validateWriteTransfer(n *TransferNetwork, p *WriteTransfer, targets, confirms []string, size uint64, now time.Time) error {
	if err := validateTransferNetwork(n, now); err != nil {
		return err
	}
	if p == nil || len(p.UploadTargets) == 0 || len(p.UploadTargets) > n.MaxUploadTargets || len(p.Legs) != len(targets) || !p.ExpiresAt.Equal(now.Add(time.Duration(n.PlanTTLSeconds)*time.Second)) || !finiteNonNeg(p.EstimatedSeconds) {
		return errors.New("invalid write transfer plan")
	}
	endpoints := endpointIndex(n)
	roots := map[string]bool{}
	for _, id := range p.UploadTargets {
		if roots[id] || !stringMember(confirms, id) || !stringMember(targets, id) {
			return errors.New("upload ingress must be a distinct required replica")
		}
		roots[id] = true
	}
	seen := map[string]bool{}
	up, down, outgoing, incoming := map[string]uint64{}, map[string]uint64{}, map[string]int{}, map[string]int{}
	for _, l := range p.Legs {
		if seen[l.To] || !stringMember(targets, l.To) || l.From == l.To || l.BPS == 0 || roots[l.To] != (l.From == n.Origin) || l.From != n.Origin && !roots[l.From] {
			return errors.New("invalid transfer dependency or duplicate target")
		}
		link := usableLink(n, l.From, l.To, l.Path, now)
		if link == nil || link.ThroughputBPS != 0 && l.BPS > link.ThroughputBPS {
			return errors.New("unobserved, stale or over-budget transfer link")
		}
		var overflow bool
		up[l.From], overflow = addOverflow(up[l.From], l.BPS)
		if overflow {
			return errors.New("upload budget overflow")
		}
		down[l.To], overflow = addOverflow(down[l.To], l.BPS)
		if overflow {
			return errors.New("download budget overflow")
		}
		outgoing[l.From]++
		incoming[l.To]++
		seen[l.To] = true
	}
	for id, endpoint := range endpoints {
		u, d := availableBandwidth(endpoint)
		if up[id] > u || down[id] > d || outgoing[id] > min(n.MaxConcurrent, endpoint.MaxConcurrent) || incoming[id] > min(n.MaxConcurrent, endpoint.MaxConcurrent) {
			return errors.New("shared endpoint bandwidth or concurrency exceeded")
		}
	}
	if len(seen) != len(targets) {
		return errors.New("transfer does not reach every replica target")
	}
	seconds := transferDuration(n.Origin, p.Legs, size)
	if seconds > float64(n.PlanTTLSeconds) || math.Abs(seconds-p.EstimatedSeconds) > 1e-9 {
		return errors.New("transfer completion estimate differs from budgeted dependencies")
	}
	return nil
}
