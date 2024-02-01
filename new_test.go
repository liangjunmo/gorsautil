package gorsautil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	_, err := NewPrivateKeyWithFile("./testdata/private.pem")
	require.Nil(t, err)

	_, err = NewPublicKeyWithFile("./testdata/public.pem")
	require.Nil(t, err)
}
