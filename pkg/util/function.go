package util

// 定义一个泛型 Function 类型，它接受任意数量的任意类型的参数
type Function func(args ...interface{})

func Combine(functions ...Function) Function {
	return func(args ...interface{}) {
		for _, function := range functions {
			function(args...)
		}
	}
}
