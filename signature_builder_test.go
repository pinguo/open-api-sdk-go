package sdk

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSigRequest(t *testing.T) {
	sb := NewSignatureBuilder("ak", "sk", 3600)
	body := strings.NewReader("a=b&d=c")
	r, _ := http.NewRequest("POST", "https://api.open-platform.com/v1/photos/generate?data=a", body)

	ts, err := sb.SignRequest(context.Background(), r)
	if err != nil {
		t.Error(err)
	}
	t.Log(*ts)
	t.Log(r.Header)

	err = sb.ValidateRequest(context.Background(), r)
	if err != nil {
		t.Error(err)
	}
}

func TestSignResponse(t *testing.T) {
	sb := NewSignatureBuilder("ak", "sk", 3600)
	request, _ := http.NewRequest("GET", "https://api.open-platform.com/v1/photos/generate?data=a", nil)
	response := &http.Response{
		Request: request,
		Body:    io.NopCloser(strings.NewReader("aaaaaaa")),
		Header:  map[string][]string{},
	}
	rs, err := sb.SignResponseBody(context.Background(), request.URL.Path, []byte("aaaaaaa"))
	if err != nil {
		t.Error(err)
	}
	t.Log(*rs)
	t.Log(response.Header)
	response.Header.Set(HeadKeySign, rs.Sign)
	response.Header.Set(HeadKeyTimestamp, rs.Timestamp)
	response.Header.Set(HeadKeyAccessKey, rs.AccessKey)

	err = sb.ValidateResponse(context.Background(), response)
	if err != nil {
		t.Error(err)
	}
}
