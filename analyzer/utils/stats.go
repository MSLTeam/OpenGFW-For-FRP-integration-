package utils

import "math"

// ShannonEntropy returns the Shannon entropy (base-2) of bs.
func ShannonEntropy(bs []byte) float64 {
	if len(bs) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range bs {
		freq[b]++
	}
	invN := 1.0 / float64(len(bs))
	var ent float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) * invN
		ent -= p * math.Log2(p)
	}
	return ent
}

func PrintableRatio(bs []byte) float64 {
	if len(bs) == 0 {
		return 0
	}
	n := 0
	for _, b := range bs {
		if b >= 0x20 && b <= 0x7e {
			n++
		}
	}
	return float64(n) / float64(len(bs))
}
