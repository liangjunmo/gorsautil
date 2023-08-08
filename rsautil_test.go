package rsautil_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/liangjunmo/rsautil"
)

func Test(t *testing.T) {
	privateKey, err := rsautil.NewPrivateKeyWithFile("./private.pem")
	assert.Nil(t, err)

	publicKey, err := rsautil.NewPublicKeyWithFile("./public.pem")
	assert.Nil(t, err)

	signature, err := rsautil.SignWithSHA256(privateKey, "hello world")
	assert.Nil(t, err)

	err = rsautil.VerifySignatureWithSHA256(publicKey, "hello world", signature)
	assert.Nil(t, err)

	var (
		method    = "POST"
		url       = "url"
		timestamp = time.Now().Unix()
		random    = "123456"
		body      = "body"
		message   = rsautil.BuildSignMessage(method, url, timestamp, random, body)
	)

	signature, err = rsautil.SignHttpRequestWithSHA256(privateKey, method, url, timestamp, random, body)
	assert.Nil(t, err)

	err = rsautil.VerifySignatureWithSHA256(publicKey, message, signature)
	assert.Nil(t, err)
}
