package sign

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

func TestSigRequestWithHeaders(t *testing.T) {
    sb := NewSignatureBuilder("ak", "sk", 3600)
    r, _ := http.NewRequest("GET", "https://api.open-platform.com/v1/test?x=1", nil)
    // business headers that should participate in signing
    r.Header.Set("PG-Client", "ios")
    r.Header.Set("PG-Trace-Id", "abc")

    // sign
    if _, err := sb.SignRequest(context.Background(), r); err != nil {
        t.Fatal(err)
    }
    // validate should pass
    if err := sb.ValidateRequest(context.Background(), r); err != nil {
        t.Fatalf("validate failed: %v", err)
    }

    // mutate a participating header -> should fail
    r.Header.Set("PG-Client", "android")
    if err := sb.ValidateRequest(context.Background(), r); err == nil {
        t.Fatalf("expected validation failure when PG-Client changed")
    }

    // change method should also change signature
    r2, _ := http.NewRequest("POST", r.URL.String(), nil)
    r2.Header = r.Header.Clone()
    if _, err := sb.SignRequest(context.Background(), r2); err != nil {
        t.Fatal(err)
    }
    if err := sb.ValidateRequest(context.Background(), r2); err != nil {
        t.Fatalf("validate failed after re-sign with method POST: %v", err)
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
