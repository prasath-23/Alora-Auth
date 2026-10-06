// Package models holds the health feature's DTOs and HTTP response models.
package models

// Pressure is the memory reading behind the load-shedding probe.
type Pressure struct {
	Overloaded bool
	Heap       uint64
	RSS        uint64
}
