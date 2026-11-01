package controlplane

// Compatibility with the decimal ingestion/storage codec in VictoriaMetrics
// v1.128.0, lib/decimal/decimal.go (FromFloat, AppendFloatToDecimal, ToFloat).
// Upstream: VictoriaMetrics/VictoriaMetrics, Apache-2.0, Copyright 2019
// VictoriaMetrics Authors. This implementation has local names and explicit
// error/budget boundaries; it is not a tolerance/epsilon comparison.
// See https://github.com/VictoriaMetrics/VictoriaMetrics/blob/v1.128.0/lib/decimal/decimal.go
import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"sort"
	"strconv"
)

func migrationVMDecimal(value float64) (int64, int, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, 0, ErrMigrationRecovery
	}
	if value == 0 {
		return 0, 0, nil
	}
	negative := value < 0
	if negative {
		value = -value
	}
	n, scale := migrationVMPositiveDecimal(value)
	if negative {
		n = -n
		if n < math.MinInt64+1 {
			n = math.MinInt64 + 1
		}
	} else if n > math.MaxInt64-2 {
		n = math.MaxInt64 - 2
	}
	return n, scale, nil
}

func migrationVMPositiveDecimal(value float64) (int64, int) {
	whole := uint64(value)
	if value < math.Exp2(64) && float64(whole) == value {
		scale := 0
		for whole >= uint64(1)<<55 {
			whole /= 10
			scale++
		}
		for whole != 0 && whole%10 == 0 {
			whole /= 10
			scale++
		}
		return int64(whole), scale
	}
	precision, scale := float64(1e12), 0
	if value > 1e6 || value < 1e-6 {
		if value > 1e6 {
			precision = 1e15
		}
		_, binaryExponent := math.Frexp(value)
		binaryExponent = max(-1022, min(1023, binaryExponent))
		scale = int(float64(binaryExponent) * (math.Ln2 / math.Ln10))
		value *= math.Pow10(-scale)
	}
	for value < precision {
		integer, fraction := math.Modf(value)
		if fraction*precision < integer {
			value = integer
			break
		}
		if (1-fraction)*precision < integer {
			value = integer + 1
			break
		}
		value *= 100
		scale -= 2
	}
	whole = uint64(value)
	if whole%10 == 0 {
		whole /= 10
		scale++
	}
	return int64(whole), scale
}

func migrationVMDecimalFloat(v int64, e int) float64 {
	if e < 0 {
		return float64(v) / math.Pow10(-e)
	}
	if e > 0 {
		return float64(v) * math.Pow10(e)
	}
	return float64(v)
}

// Storage uses one safe decimal scale for each encoded series block. Values
// with a smaller scale can lose digits when a larger value needs the integer
// range. The exact shared-scale rule is reproduced; unsupported surrounding
// storage/block history remains a mismatch rather than being guessed.
func migrationVMDecimalSeries(values []float64) ([]float64, error) {
	encoded := make([]int64, len(values))
	scales := make([]int, len(values))
	minimum, maximum := math.MaxInt, math.MinInt
	for i, v := range values {
		n, e, err := migrationVMDecimal(v)
		if err != nil {
			return nil, err
		}
		encoded[i], scales[i] = n, e
		minimum = min(minimum, e)
		maximum = max(maximum, e)
	}
	if len(values) == 0 {
		return nil, ErrMigrationRecovery
	}
	if minimum != maximum {
		for i, n := range encoded {
			room := 1024
			if n != 0 {
				u := uint64(n)
				if n < 0 {
					u = uint64(-(n + 1)) + 1
				}
				room = 0
				for u <= uint64(math.MaxInt64/10) {
					u *= 10
					room++
				}
			}
			minimum = max(minimum, scales[i]-room)
		}
	}
	result := make([]float64, len(values))
	for i, n := range encoded {
		shift := scales[i] - minimum
		if shift < 0 {
			if shift < -18 {
				n = 0
			} else {
				for ; shift < 0; shift++ {
					n /= 10
				}
			}
		} else {
			for ; shift > 0; shift-- {
				n *= 10
			}
		}
		result[i] = migrationVMDecimalFloat(n, minimum)
		if math.IsNaN(result[i]) || math.IsInf(result[i], 0) {
			return nil, ErrMigrationRecovery
		}
		if result[i] == 0 {
			result[i] = 0
		}
	}
	return result, nil
}

func migrationRecoveryExpectedMetricMap(raw []byte) (map[string]string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	type series struct {
		line   migrationMetricLine
		values map[int64]float64
	}
	groups := map[string]*series{}
	count := 0
	for {
		var line migrationMetricLine
		err := decoder.Decode(&line)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrMigrationRecovery
		}
		if _, err = migrationRecoveryHostMetricMap([]migrationMetricLine{line}); err != nil {
			return nil, err
		}
		label, _ := json.Marshal(line.Metric)
		key := string(label)
		group := groups[key]
		if group == nil {
			group = &series{line: migrationMetricLine{Metric: line.Metric}, values: map[int64]float64{}}
			groups[key] = group
		}
		for i, at := range line.Timestamps {
			value := line.Values[i]
			if old, ok := group.values[at]; ok && old != value {
				return nil, ErrMigrationRecovery
			}
			group.values[at] = value
			count++
			if count > migrationRecoveryHostMaxSamples {
				return nil, ErrMigrationRecovery
			}
		}
	}
	out := map[string]string{}
	for label, group := range groups {
		times := make([]int64, 0, len(group.values))
		for at := range group.values {
			times = append(times, at)
		}
		sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
		values := make([]float64, len(times))
		for i, at := range times {
			values[i] = group.values[at]
		}
		normalized, err := migrationVMDecimalSeries(values)
		if err != nil {
			return nil, err
		}
		for i, at := range times {
			out[label+":"+strconv.FormatInt(at, 10)] = strconv.FormatFloat(normalized[i], 'g', -1, 64)
		}
	}
	return out, nil
}
