package util

import (
	"strings"
)

// AggregateError 聚合多个错误
type AggregateError []error

// Error 实现 error 接口
func (agg AggregateError) Error() string {
	var errorMessages []string
	for _, err := range agg {
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
		}
	}
	return strings.Join(errorMessages, ", ")
}

// NewAggregate 创建一个聚合错误
func NewAggregate(errs []error) error {
	// 移除空错误
	var nonNilErrors []error
	for _, err := range errs {
		if err != nil {
			nonNilErrors = append(nonNilErrors, err)
		}
	}

	if len(nonNilErrors) == 0 {
		return nil
	}

	return AggregateError(nonNilErrors)
}
