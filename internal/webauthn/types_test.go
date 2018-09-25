package webauthn

import (
	"fmt"
	"reflect"
	"testing"
)

func TestAuthData_UnmarshalBinary(t *testing.T) {
	eccKey := &COSEPublicKey{
		Type: COSEAlgorithmES256,
		X:    []byte{1, 2, 3, 4},
		Y:    []byte{9, 8, 7, 6},
	}

	cases := []struct {
		AuthData []byte
		Expected *AuthData
	}{
		{
			AuthData: []byte{
				// RPID: 32 bytes
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
				// Flags: 1 byte
				0x01,
				// Counter: 4 bytes (big endian)
				0x01, 0x02, 0x03, 0x04,
				// AAGUID: 16 bytes
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
				// Length: 2 bytes
				0, 4,
				// Credential ID
				9, 8, 7, 6,
				// Public Key (CBOR encoded)
				// http://cbor.me/?bytes=A5(20-00-21-44(01020304)-22-44(09080706)-01-00-03-26)
				0xa5, 0x20, 0x00, 0x21, 0x44, 0x01, 0x02, 0x03, 0x04, 0x22, 0x44, 0x09, 0x08, 0x07, 0x06, 0x01, 0x00, 0x03, 0x26,
			},
			Expected: &AuthData{
				RPIDHash:            []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
				Flags:               0x01,
				Counter:             uint32(0x01020304),
				AAGUID:              []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
				CredentialID:        []byte{9, 8, 7, 6},
				CredentialPublicKey: eccKey,
			},
		},
	}

	for i, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			decoded := new(AuthData)
			err := decoded.UnmarshalBinary(tc.AuthData)
			if err != nil {
				t.Fatal(err)
			} else if !reflect.DeepEqual(tc.Expected, decoded) {
				t.Fatalf("want: %v, got %v", tc.Expected, decoded)
			}
		})
	}
}

func TestDecodeAuthData_InvalidValues(t *testing.T) {
	// TODO
}
