package core

import (
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes"
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

// mustTs converts the time into a timestamp, or panics
//
// a timestamp is valid unless it is outside the range of [0001-01-01,
// 10000-01-01], so seeing that in practice is totally unreasonable and panic
// worthy
func mustTs(t time.Time) *timestamp.Timestamp {
	ts, err := ptypes.TimestampProto(t)
	if err != nil {
		panic(fmt.Sprintf("failed to convert %s to protobuf.Timestamp: %v", t.String(), err))
	}
	return ts
}
