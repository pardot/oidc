package core

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPBStructConversion(t *testing.T) {
	var in = map[string]interface{}{
		"string": "string",
		"number": 1234.5,
		"bool":   true,
		"list":   []interface{}{"one, two"},
		"map": map[string]interface{}{
			"substring": "sub",
		},
	}

	pb, err := goToPBStruct(in)
	if err != nil {
		t.Fatal(err)
	}

	out, err := pbstructToGo(pb)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(in, out); diff != "" {
		t.Errorf("want(-) got (+) %s", diff)
	}
}
