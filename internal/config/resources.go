package config

import "math"

// WorkerResources are ceilings, not reservations or promised memory bounds.
// Zero selects the measured default; it does not disable a ceiling. This also
// keeps older durable jobs and programmatic zero-value configurations readable.
type WorkerResources struct {
	CPUs      int64 `yaml:"cpus"`
	MemoryMiB int64 `yaml:"memory_mib"`
}

func (r WorkerResources) Effective() WorkerResources {
	if r.CPUs == 0 {
		r.CPUs = 2
	}
	if r.MemoryMiB == 0 {
		r.MemoryMiB = 512
	}
	return r
}

func (r WorkerResources) Validate() error {
	r = r.Effective()
	if r.CPUs < 1 || r.CPUs > math.MaxInt64/1_000_000_000 || r.MemoryMiB < 1 || r.MemoryMiB > math.MaxInt64/(1<<20) {
		return ErrInvalid
	}
	return nil
}
