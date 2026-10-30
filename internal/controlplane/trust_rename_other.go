//go:build !linux && !darwin

package controlplane

func publishTrustDirectory(fd int, from, to string) error { return errTrustStorage }
