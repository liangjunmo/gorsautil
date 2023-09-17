package gorsautil_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/liangjunmo/gorsautil"
)

func TestNew(t *testing.T) {
	_, err := gorsautil.NewPrivateKeyWithFile("./testdata/private.pem")
	assert.Nil(t, err)

	_, err = gorsautil.NewPublicKeyWithFile("./testdata/public.pem")
	assert.Nil(t, err)
}
