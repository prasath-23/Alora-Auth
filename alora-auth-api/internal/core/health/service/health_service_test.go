package service

import "testing"

func TestOverloadedSamplesAtMostOncePerInterval(t *testing.T) {
	heap, reads := uint64(0), 0
	s := &healthService{read: func() (uint64, uint64) { reads++; return heap, 0 }}

	if s.Overloaded() {
		t.Fatal("overloaded with an empty heap")
	}
	// Over the ceiling now, but the verdict is cached for the interval: the
	// counters must not be re-read on every request.
	heap = maxHeapBytes + 1
	for range 100 {
		if s.Overloaded() {
			t.Fatal("re-read before the sample interval elapsed")
		}
	}
	if reads != 1 {
		t.Fatalf("read the counters %d times, want 1", reads)
	}

	s.nextSample.Store(0) // the interval has elapsed
	if !s.Overloaded() {
		t.Fatal("not overloaded with the heap over its ceiling")
	}
	if reads != 2 {
		t.Fatalf("read the counters %d times, want 2", reads)
	}
}

func TestPressureChecksBothCeilings(t *testing.T) {
	for _, c := range []struct {
		heap, rss uint64
		want      bool
	}{
		{maxHeapBytes, maxRSSBytes, false}, // at the ceiling is not over it
		{maxHeapBytes + 1, 0, true},
		{0, maxRSSBytes + 1, true},
	} {
		s := &healthService{read: func() (uint64, uint64) { return c.heap, c.rss }}
		if got := s.Pressure(); got.Overloaded != c.want || got.Heap != c.heap || got.RSS != c.rss {
			t.Errorf("heap %d rss %d: got %+v, want overloaded=%v", c.heap, c.rss, got, c.want)
		}
	}
}
