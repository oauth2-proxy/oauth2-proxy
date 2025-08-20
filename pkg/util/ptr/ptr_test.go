package ptr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPtr(t *testing.T) {
	p := Ptr(42)
	assert.NotNil(t, p)
	assert.Equal(t, 42, *p)

	s := Ptr("hello")
	assert.NotNil(t, s)
	assert.Equal(t, "hello", *s)

	b := Ptr(true)
	assert.NotNil(t, b)
	assert.True(t, *b)
}

func TestDeref(t *testing.T) {
	v := Deref(Ptr(99), 0)
	assert.Equal(t, 99, v)

	v = Deref[int](nil, 123)
	assert.Equal(t, 123, v)

	s := Deref[string](nil, "default")
	assert.Equal(t, "default", s)

	b := Deref(Ptr(true), false)
	assert.True(t, b)

	b = Deref[bool](nil, false)
	assert.False(t, b)
}
