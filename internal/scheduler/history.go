package scheduler

import (
	"math"
	"sort"
	"time"
)

// ---------------------------------------------------------------------------
// NodeHistory: pure-function sampling / per-period availability prediction.
//
// This is deliberately a CONSERVATIVE minimal implementation:
//   - inputs are raw (timestamp, online) samples, outputs are pure values,
//     no state, no clock reads (now is always a parameter);
//   - per-period prediction buckets samples by UTC hour-of-day and uses the
//     matching bucket only when it holds enough samples. With the default
//     24h sample span an hour bucket holds at most one hourly sample, so
//     the bucket path cannot engage — it needs multi-day history. The
//     prediction is then a conservative overall-ratio blend over a finite
//     horizon; it does NOT learn diurnal or other multi-period cycles and
//     must not be described as having done so;
//   - when samples are insufficient (below MinHistorySamples), it returns a
//     conservative low-confidence prediction so downstream hard gates treat
//     the node as UNPROVEN rather than healthy;
//   - confidence is capped below 1 (history can never fully vouch for a
//     node) and decays with sample scarcity and with offline churn.
// ---------------------------------------------------------------------------

const (
	// MinHistorySamples: below this the prediction is conservative.
	MinHistorySamples = 8
	// MinBucketSamples: per-hour bucket needs at least this many samples
	// to be trusted over the overall ratio.
	MinBucketSamples = 3
	// MaxHistoryConfidence caps forecast confidence derived from history.
	MaxHistoryConfidence = 0.95
	// HistorySampleSpanSeconds: only samples within this window before
	// `now` are used (24h; keeps per-period stats relevant). Note: within a
	// 24h span the hour-of-day bucket logic cannot engage (one hourly
	// sample per bucket) — see the package comment; no diurnal cycle is
	// being learned.
	HistorySampleSpanSeconds = 86400
	// conservativeOfflineSpellSeconds is reported for an offline node with
	// insufficient history: long enough that no policy may classify the
	// outage as "routine offline, defer".
	conservativeOfflineSpellSeconds = 365 * 24 * 3600
)

// Prediction is the pure output of history analysis.
type Prediction struct {
	// ProbabilityOnline: P(continuously online over the requested horizon).
	ProbabilityOnline float64
	// Confidence in [0, 0.95]; below Policy.MinConfidence downstream math
	// treats the node conservatively.
	Confidence float64
	// OfflineSpellSeconds: expected duration of a typical offline spell
	// (seconds). For a currently-offline node this is the expected total
	// length of the current spell. 0 when no offline spell is expected.
	OfflineSpellSeconds float64
	// SamplesUsed / Conservative bookkeeping for reasons strings.
	SamplesUsed  int
	Conservative bool
	Source       string // "history" | "forecast" | "conservative"
}

// ParseSample parses an OnlineSample's RFC3339 timestamp; errors are
// returned so the caller (validator) can reject malformed input.
func ParseSample(s OnlineSample) (time.Time, error) {
	return time.Parse(time.RFC3339, s.At)
}

// PredictFromHistory is a pure function:
// (samples, now, horizon, currentlyOnline) -> Prediction.
// currentlyOnline must be supplied by the caller (the raw sample log does
// not necessarily end at `now`). It never mutates inputs and never reads
// the wall clock.
func PredictFromHistory(samples []OnlineSample, now time.Time, horizonSeconds int, currentlyOnline bool) Prediction {
	horizonSeconds = normalizeHorizon(horizonSeconds)

	parsed := make([]struct {
		at     time.Time
		online bool
	}, 0, len(samples))
	for _, s := range samples {
		t, err := ParseSample(s)
		if err != nil || t.After(now) {
			continue // malformed or future samples ignored (pure filtering)
		}
		parsed = append(parsed, struct {
			at     time.Time
			online bool
		}{t, s.Online})
	}
	sort.Slice(parsed, func(i, j int) bool { return parsed[i].at.Before(parsed[j].at) })

	// Keep only the recent span.
	cutoff := now.Add(-time.Duration(HistorySampleSpanSeconds) * time.Second)
	recent := parsed[:0]
	for _, p := range parsed {
		if !p.at.Before(cutoff) {
			recent = append(recent, p)
		}
	}

	if len(recent) < MinHistorySamples {
		return conservativePrediction(currentlyOnline)
	}

	// Overall availability ratio over the recent span.
	online := 0
	for _, p := range recent {
		if p.online {
			online++
		}
	}
	ratio := float64(online) / float64(len(recent))

	// Per-period (UTC hour-of-day) bucket for `now`.
	bucketTotal, bucketOnline := 0, 0
	hour := now.UTC().Hour()
	for _, p := range recent {
		if p.at.UTC().Hour() == hour {
			bucketTotal++
			if p.online {
				bucketOnline++
			}
		}
	}
	useBucket := bucketTotal >= MinBucketSamples
	prob := ratio
	if useBucket {
		prob = float64(bucketOnline) / float64(bucketTotal)
	}

	// Offline spell statistics: approximate each spell's duration from the
	// samples around it (first offline sample -> first online sample after).
	spells := offlineSpellSeconds(recent, now)
	meanSpell := mean(spells)

	// Confidence: grows with sample count, is reduced when the periodic
	// bucket is sparse, when churn (offline spells) is present, and never
	// reaches 1.0.
	conf := math.Min(MaxHistoryConfidence, float64(len(recent))/float64(4*MinHistorySamples))
	if !useBucket {
		conf *= 0.8
	}
	if len(spells) > 0 {
		conf *= math.Max(0.5, 1-0.1*float64(len(spells)))
	}

	// Horizon scaling: for short horizons, a currently-online node with a
	// high ratio stays near the ratio; for long horizons shrink toward the
	// ratio (a crude, deliberately conservative monotone blend). We never
	// claim better than the observed ratio.
	scaled := math.Min(prob, ratio+(1-ratio)*math.Min(1.0, 86400.0/float64(horizonSeconds)))
	if !currentlyOnline {
		// A node that is offline right now cannot be "continuously online"
		// unless its typical spell is shorter than the horizon — and even
		// then we only grant the ratio, discounted by spell risk.
		if meanSpell > 0 && meanSpell < 0.5*float64(horizonSeconds) {
			scaled = math.Min(scaled, 0.5*ratio)
		} else {
			scaled = 0
		}
	}

	spell := meanSpell
	if currentlyOnline {
		// For a currently-online node the policy cares whether routine
		// offline spells exist at all (e.g. nightly maintenance windows).
		if len(spells) == 0 {
			spell = 0
		}
	}

	return Prediction{
		ProbabilityOnline:   clamp01(scaled),
		Confidence:          clamp01(conf),
		OfflineSpellSeconds: spell,
		SamplesUsed:         len(recent),
		Source:              "history",
	}
}

// conservativePrediction is returned when history is insufficient: an
// online node is "unproven" (p=0.5, confidence 0 -> downstream gates treat
// it as may-fail), an offline node is assumed offline for a very long time
// (never classifiable as routine).
func conservativePrediction(currentlyOnline bool) Prediction {
	if currentlyOnline {
		return Prediction{ProbabilityOnline: 0.5, Confidence: 0, OfflineSpellSeconds: 0,
			SamplesUsed: 0, Conservative: true, Source: "conservative"}
	}
	return Prediction{ProbabilityOnline: 0, Confidence: 0,
		OfflineSpellSeconds: conservativeOfflineSpellSeconds,
		SamplesUsed:         0, Conservative: true, Source: "conservative"}
}

// offlineSpellSeconds approximates offline spell durations in seconds from
// consecutive samples. The last (possibly ongoing) spell is measured up to
// `now`. Pure; deterministic.
func offlineSpellSeconds(sorted []struct {
	at     time.Time
	online bool
}, now time.Time) []float64 {
	var spells []float64
	var offlineStart time.Time
	inSpell := false
	for _, p := range sorted {
		if !p.online && !inSpell {
			offlineStart = p.at
			inSpell = true
		} else if p.online && inSpell {
			spells = append(spells, p.at.Sub(offlineStart).Seconds())
			inSpell = false
		}
	}
	if inSpell {
		spells = append(spells, now.Sub(offlineStart).Seconds())
	}
	return spells
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range xs {
		if !math.IsInf(x, 0) && !math.IsNaN(x) {
			sum += x
		}
	}
	return sum / float64(len(xs))
}

func normalizeHorizon(h int) int {
	if h <= 0 {
		return 86400
	}
	return h
}
