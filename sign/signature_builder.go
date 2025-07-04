package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

func NewSignatureBuilder(ak, sk string, expiredIn int) *SignatureBuilder {
	return &SignatureBuilder{
		accessKey: ak,
		secretKey: sk,
		expiredIn: expiredIn,
	}
}

type SignatureResult struct {
	FinalText string
	Timestamp string
	Sign      string
	AccessKey string
}

type SignatureBuilder struct {
	accessKey string
	secretKey string
	expiredIn int
}

func (s *SignatureBuilder) SignResponseBody(ctx context.Context, reqPath string, body []byte) (*SignatureResult, error) {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	finalText := fmt.Sprintf("%s%s%s%s", reqPath, s.buildParamsSignatureText(map[string]string{}, string(body)), ts, s.secretKey)
	sign := s.hash(finalText)
	return &SignatureResult{
		Sign:      sign,
		AccessKey: s.accessKey,
		FinalText: finalText,
		Timestamp: ts,
	}, nil
}

func (s *SignatureBuilder) ValidateResponse(ctx context.Context, res *http.Response) error {
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	res.Body = io.NopCloser(bytes.NewBuffer(body))
	ts := res.Header.Get(HeadKeyTimestamp)
	if ts == "" {
		return fmt.Errorf("timestamp missing in response header")
	}
	sign := res.Header.Get(HeadKeySign)
	if sign == "" {
		return fmt.Errorf("signature missing in response header")
	}
	ak := res.Header.Get(HeadKeyAccessKey)
	if ak != s.accessKey {
		return fmt.Errorf("access key validation failed")
	}
	if ak != s.accessKey {
		return fmt.Errorf("access key validation failed")
	}
	signText := s.buildParamsSignatureText(map[string]string{}, string(body))
	path := res.Request.URL.Path
	finalText := fmt.Sprintf("%s%s%s%s", path, signText, ts, s.secretKey)
	resSign := s.hash(finalText)
	if resSign == sign {
		return nil
	}
	return fmt.Errorf("signature validation failed")
}

func (s *SignatureBuilder) ValidateRequest(ctx context.Context, r *http.Request) error {
	ts := r.Header.Get(HeadKeyTimestamp)
	timestamp, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return err
	}
	if s.expiredIn > 0 && int(time.Now().Unix()-timestamp) > s.expiredIn {
		return fmt.Errorf("timestamp expired")
	}

	rs, err := s.buildSignatureFromIncomeRequest(ctx, r)
	if err != nil {
		return err
	}
	if rs.Sign != r.Header.Get(HeadKeySign) {
		return fmt.Errorf("signature validation failed")
	}
	return nil
}

func (s *SignatureBuilder) SignRequest(ctx context.Context, r *http.Request) (*SignatureResult, error) {
	rs, err := s.buildSignatureFromIncomeRequest(ctx, r)
	if err != nil {
		return nil, err
	}

	r.Header.Set(HeadKeyTimestamp, rs.Timestamp)
	r.Header.Set(HeadKeyAccessKey, s.accessKey)
	r.Header.Set(HeadKeySign, rs.Sign)
	return rs, nil
}

func (s *SignatureBuilder) buildSignatureFromIncomeRequest(ctx context.Context, r *http.Request) (*SignatureResult, error) {
	queryParams := s.getGETParams(r)
	body, postParams, err := s.getPOSTParams(r)
	if err != nil {
		return nil, err
	}
	if len(postParams) > 0 {
		for k, v := range postParams {
			queryParams[k] = v
		}
	}

	ts := r.Header.Get(HeadKeyTimestamp)
	if ts == "" {
		ts = fmt.Sprintf("%d", time.Now().Unix())
	}
	path := r.URL.Path
	finalText := fmt.Sprintf("%s%s%s%s", path, s.buildParamsSignatureText(queryParams, body), ts, s.secretKey)
	sign := s.hash(finalText)
	return &SignatureResult{
		Sign:      sign,
		FinalText: finalText,
		Timestamp: ts,
	}, nil
}

// 计算 MD5 哈希值
func (s *SignatureBuilder) hash(text string) string {
	hash := sha256.Sum256([]byte(text))
	return fmt.Sprintf("%x", hash)
}

func (s *SignatureBuilder) buildParamsSignatureText(params map[string]string, body string) string {
	// 获取所有键并排序
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 拼接参数和值
	var paramStr string
	for _, k := range keys {
		paramStr += fmt.Sprintf("%s=%s", k, params[k])
	}
	return paramStr + body
}
func (s *SignatureBuilder) getGETParams(r *http.Request) map[string]string {
	params := make(map[string]string)
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			params[key] = values[0]
		}
	}
	return params
}

// 从 HTTP POST 请求中提取参数
func (s *SignatureBuilder) getPOSTParams(r *http.Request) (string, map[string]string, error) {
	const defaultContentType = "application/x-www-form-urlencoded"
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		ct = defaultContentType
	}
	ct, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse content type: %v", err)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read request body: %v", err)
	}

	r.Body = io.NopCloser(bytes.NewBuffer(body))
	if strings.Contains(ct, "application/json") {
		// 把读取的内容重新放回 Body 中，以便后续处理不影响原请求
		return string(body), nil, nil
	}
	// 如果是其他类型，尝试解析为表单数据
	if strings.Contains(ct, defaultContentType) {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return "", nil, fmt.Errorf("failed to parse form data: %v", err)
		}
		params := make(map[string]string)
		for k, _ := range values {
			params[k] = values.Get(k)
		}
		return "", params, nil
	}
	return "", nil, fmt.Errorf("unsupported content type: " + ct)
}
