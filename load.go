package oidc

import (
	"fmt"

	"github.com/Jing-ze/oauth2-proxy/pkg/apis/options"
	"github.com/Jing-ze/oauth2-proxy/pkg/mapstructure"
	"github.com/Jing-ze/oauth2-proxy/pkg/validation"

	"github.com/tidwall/gjson"
)

func LoadOptions(json gjson.Result) (*options.Options, error) {
	input := gjsonToResultMap(json)
	opts, err := loadLegacyOptions(input)
	if err = validation.Validate(opts); err != nil {
		return opts, err
	}
	return opts, err
}

// loadLegacyOptions loads the old toml options using the legacy flag set
// and legacy options struct.
func loadLegacyOptions(input map[string]interface{}) (*options.Options, error) {

	legacyOpts := options.NewLegacyOptions()

	err := mapstructure.Decode(input, &legacyOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to decode input: %v", err)
	}

	opts, err := legacyOpts.ToOptions()
	if err != nil {
		return nil, fmt.Errorf("failed to convert config: %v", err)
	}

	return opts, nil
}

func gjsonToResultMap(result gjson.Result) map[string]interface{} {
	// 我们需要一个 map 来对应 JSON 对象
	resultMap := make(map[string]interface{})

	// 遍历 JSON 对象的每个成员
	result.ForEach(func(key, value gjson.Result) bool {
		resultMap[key.String()] = gjsonToInterface(value)
		return true // 继续遍历
	})

	return resultMap
}

// gjsonToInterface 将 gjson.Result 转换为 interface{}
func gjsonToInterface(result gjson.Result) interface{} {
	switch {
	case result.IsArray():
		// Result 是一个数组，转换每个元素
		values := result.Array()
		array := make([]interface{}, len(values))
		for i, value := range values {
			array[i] = gjsonToInterface(value)
		}
		return array
	case result.IsObject():
		// Result 是一个对象，转换每个成员
		objMap := make(map[string]interface{})
		result.ForEach(func(key, value gjson.Result) bool {
			objMap[key.String()] = gjsonToInterface(value)
			return true // 继续遍历
		})
		return objMap
	default:
		// 为空或为其他复杂类型
		return result.Value()
	}
}
