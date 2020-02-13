package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	corev1beta1 "github.com/pardot/oidc/proto/core/v1beta1"
)

func TestVersionedSessions(t *testing.T) {
	now := time.Now()
	pnow, _ := ptypes.TimestampProto(now)

	for _, tc := range []struct {
		Name string
		Data interface{}
		Want *sessionV2
	}{
		{
			Name: "Current format",
			Data: &versionedSession{
				Version: sessionv2,
				Session: json.RawMessage([]byte(`{
					"id": "test-id"
				}`)),
			},
			Want: &sessionV2{
				ID: "test-id",
			},
		},
		{
			Name: "v1 format",
			Data: &corev1beta1.Session{
				Id:        "test-1",
				ExpiresAt: pnow,
				AuthCode: &corev1beta1.StoredToken{
					Bcrypted:  []byte("binary-data"),
					ExpiresAt: pnow,
				},
			},
			Want: &sessionV2{
				ID:    "test-1",
				Stage: "requested",
				AuthCode: &accessToken{
					Bcrypted: []byte("binary-data"),
					Expiry:   now,
				},
				Expiry: now,
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			const id = "test-id"
			ctx := context.Background()

			sm := &mockSmgr{
				t:    t,
				id:   id,
				data: tc.Data,
			}

			// fetch it
			got, err := getSession(ctx, sm, id)
			if err != nil {
				t.Fatalf("getting: %v", err)
			}
			if got == nil {
				t.Fatal("unexpected nil session")
			}

			log.Printf("got: %v", got)
			log.Printf("want: %v", tc.Want)
			if diff := cmp.Diff(tc.Want, got); diff != "" {
				t.Errorf("first get: %v", diff)
			}

			// put it back
			if err := putSession(ctx, sm, got); err != nil {
				t.Fatalf("putting: %v", err)
			}

			// try and get it again
			got, err = getSession(ctx, sm, id)
			if err != nil {
				t.Fatalf("getting: %v", err)
			}
			if got == nil {
				t.Fatal("unexpected nil session")
			}

			if diff := cmp.Diff(tc.Want, got); diff != "" {
				t.Errorf("second get: %v", diff)
			}
		})
	}
}

type mockSmgr struct {
	SessionManager
	t    *testing.T
	id   string
	data interface{}
}

func (m *mockSmgr) GetSession(_ context.Context, sessionID string, into Session) (found bool, err error) {
	if sessionID != m.id {
		return false, nil
	}

	// convert our source into the appropriate serialized format, based on if jsonpb or json was used originally
	var jb []byte
	switch v := m.data.(type) {
	case *versionedSession:
		m.t.Log("original is versioned session")
		if v.Version != sessionv2 {
			return false, fmt.Errorf("want stored session v2, got: %s", v.Version)
		}
		jb, err = json.Marshal(v)
	case proto.Message:
		m.t.Log("original is proto.Message")
		js, e := (&jsonpb.Marshaler{}).MarshalToString(v)
		jb = []byte(js)
		err = e
	default:
		m.t.Log("original is not proto.Message")
		return false, fmt.Errorf("unexpected type: %T", m.data)
	}
	if err != nil {
		return false, fmt.Errorf("marshaling original: %v", err)
	}

	// unmarshal using go, as we expect implementations to do regardless of the
	// data origin.
	return true, json.Unmarshal(jb, into)

}

// PutSession should persist the new state of the session
func (m *mockSmgr) PutSession(_ context.Context, sess Session) error {
	vs, ok := sess.(*versionedSession)
	if !ok {
		return fmt.Errorf("tried to put non *versionedSession")
	}
	m.data = vs
	return nil
}
