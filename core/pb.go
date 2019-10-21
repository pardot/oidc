package core

import (
	"fmt"

	structpb "github.com/golang/protobuf/ptypes/struct"
)

func pbstructToGo(strct *structpb.Struct) (map[string]interface{}, error) {
	ret := make(map[string]interface{})
	for k, v := range strct.Fields {
		r, err := pbvalueToGo(v)
		if err != nil {
			return nil, err
		}
		ret[k] = r
	}
	return ret, nil
}

func pbvalueToGo(val *structpb.Value) (interface{}, error) {
	switch kind := val.Kind.(type) {
	case *structpb.Value_BoolValue:
		return kind.BoolValue, nil
	case *structpb.Value_StringValue:
		return kind.StringValue, nil
	case *structpb.Value_NumberValue:
		return kind.NumberValue, nil
	case *structpb.Value_NullValue:
		return nil, nil
	case *structpb.Value_ListValue:
		var ret []interface{}
		for _, v := range kind.ListValue.Values {
			r, err := pbvalueToGo(v)
			if err != nil {
				return nil, err
			}
			ret = append(ret, r)
		}
		return ret, nil
	case *structpb.Value_StructValue:
		return pbstructToGo(kind.StructValue)
	}
	return nil, fmt.Errorf("struct value %T is of unhandled kind", val.Kind)
}

func goToPBStruct(m map[string]interface{}) (*structpb.Struct, error) {
	ret := &structpb.Struct{
		Fields: map[string]*structpb.Value{},
	}
	for k, v := range m {
		pbv, err := goToPBValue(v)
		if err != nil {
			return nil, err
		}
		ret.Fields[k] = pbv
	}
	return ret, nil
}

func goToPBValue(g interface{}) (*structpb.Value, error) {
	switch gt := g.(type) {
	case string:
		return &structpb.Value{
			Kind: &structpb.Value_StringValue{
				StringValue: gt,
			},
		}, nil
	case int:
		return &structpb.Value{
			Kind: &structpb.Value_NumberValue{
				NumberValue: float64(gt),
			},
		}, nil
	case int32:
		return &structpb.Value{
			Kind: &structpb.Value_NumberValue{
				NumberValue: float64(gt),
			},
		}, nil
	case int64:
		return &structpb.Value{
			Kind: &structpb.Value_NumberValue{
				NumberValue: float64(gt),
			},
		}, nil
	case float64:
		return &structpb.Value{
			Kind: &structpb.Value_NumberValue{
				NumberValue: gt,
			},
		}, nil
	case bool:
		return &structpb.Value{
			Kind: &structpb.Value_BoolValue{
				BoolValue: gt,
			},
		}, nil
	case []interface{}:
		lv := &structpb.ListValue{}
		for _, v := range gt {
			pbv, err := goToPBValue(v)
			if err != nil {
				return nil, err
			}
			lv.Values = append(lv.Values, pbv)
		}
		return &structpb.Value{
			Kind: &structpb.Value_ListValue{
				ListValue: lv,
			},
		}, nil
	case []string:
		lv := &structpb.ListValue{}
		for _, v := range gt {
			pbv, err := goToPBValue(v)
			if err != nil {
				return nil, err
			}
			lv.Values = append(lv.Values, pbv)
		}
		return &structpb.Value{
			Kind: &structpb.Value_ListValue{
				ListValue: lv,
			},
		}, nil
	case map[string]interface{}:
		s, err := goToPBStruct(gt)
		if err != nil {
			return nil, err
		}
		return &structpb.Value{
			Kind: &structpb.Value_StructValue{
				StructValue: s,
			},
		}, nil
	case map[string]string:
		m := make(map[string]interface{})
		for k, v := range gt {
			m[k] = v
		}
		s, err := goToPBStruct(m)
		if err != nil {
			return nil, err
		}
		return &structpb.Value{
			Kind: &structpb.Value_StructValue{
				StructValue: s,
			},
		}, nil
	}
	return nil, fmt.Errorf("map value of %T is unhandled", g)
}
