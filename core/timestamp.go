package core

import (
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
)

// tsAdd adds the duration to the given timestamp, to a precision of seconds
func tsAdd(ts *timestamp.Timestamp, d time.Duration) *timestamp.Timestamp {
	n := new(timestamp.Timestamp)
	*n = *ts
	n.Seconds = n.Seconds + int64(d/time.Second)
	return n
}

// tsAfter returns true if the compare time is after the base time. Operates at
// seconds precision
func tsAfter(base *timestamp.Timestamp, compare *timestamp.Timestamp) bool {
	return compare.Seconds > base.Seconds
}
