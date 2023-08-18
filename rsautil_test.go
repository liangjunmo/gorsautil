package gorsautil_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/liangjunmo/gorsautil"
)

func Test(t *testing.T) {
	privateKey, err := gorsautil.NewPrivateKeyWithFile("./testdata/private.pem")
	assert.Nil(t, err)

	publicKey, err := gorsautil.NewPublicKeyWithFile("./testdata/public.pem")
	assert.Nil(t, err)

	signature, err := gorsautil.SignWithSHA256(privateKey, "hello world")
	assert.Nil(t, err)

	err = gorsautil.VerifySignatureWithSHA256(publicKey, "hello world", signature)
	assert.Nil(t, err)

	var (
		method    = "POST"
		url       = "url"
		timestamp = time.Now().Unix()
		random    = "123456"
		body      = "body"
		message   = gorsautil.BuildSignMessage(method, url, timestamp, random, body)
	)

	signature, err = gorsautil.SignHttpRequestWithSHA256(privateKey, method, url, timestamp, random, body)
	assert.Nil(t, err)

	err = gorsautil.VerifySignatureWithSHA256(publicKey, message, signature)
	assert.Nil(t, err)
}
