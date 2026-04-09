package sign

import (
    "bytes"
    "context"
    "crypto/hmac"
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
    // Response signature does not include headers; use HMAC-SHA256 with SK as key and AK appended in data
    finalText := fmt.Sprintf("%s%s%s%s", reqPath, s.buildParamsSignatureText(map[string]string{}, string(body)), ts, s.accessKey)
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
    signText := s.buildParamsSignatureText(map[string]string{}, string(body))
    path := res.Request.URL.Path
    // Response validation matches SignResponseBody: HMAC over path + body + ts + AK
    finalText := fmt.Sprintf("%s%s%s%s", path, signText, ts, ak)
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
    // Validate AccessKey presence and value
    ak := r.Header.Get(HeadKeyAccessKey)
    if ak == "" {
        return fmt.Errorf("access key missing in request header")
    }
    if ak != s.accessKey {
        return fmt.Errorf("access key validation failed")
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
    method := strings.ToUpper(r.Method)
    path := r.URL.Path
    headerText := s.buildHeaderSignatureText(r.Header)
    finalText := fmt.Sprintf("%s%s%s%s%s%s", method, path, s.buildParamsSignatureText(queryParams, body), headerText, ts, s.accessKey)
    sign := s.hash(finalText)
    return &SignatureResult{
        Sign:      sign,
        FinalText: finalText,
        Timestamp: ts,
    }, nil
}

// 计算 HMAC-SHA256 哈希值，返回十六进制小写字符串
func (s *SignatureBuilder) hash(text string) string {
    mac := hmac.New(sha256.New, []byte(s.secretKey))
    mac.Write([]byte(text))
    return fmt.Sprintf("%x", mac.Sum(nil))
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

// buildHeaderSignatureText 构造 header 参数签名串
// 仅参与以 "PG-" 开头的 header，且排除 PG-Timestamp、PG-AccessKey、PG-Sign
// key 统一转为小写后进行字典序排序，拼接为 key=value 连续串
func (s *SignatureBuilder) buildHeaderSignatureText(h http.Header) string {
    if h == nil {
        return ""
    }
    excludes := map[string]struct{}{
        strings.ToLower(HeadKeyTimestamp): {},
        strings.ToLower(HeadKeyAccessKey): {},
        strings.ToLower(HeadKeySign):      {},
    }
    headers := make(map[string]string)
    for k, v := range h {
        lower := strings.ToLower(k)
        if strings.HasPrefix(lower, "pg-") {
            if _, ok := excludes[lower]; ok {
                continue
            }
            if len(v) > 0 {
                headers[lower] = v[0]
            }
        }
    }
    if len(headers) == 0 {
        return ""
    }
    keys := make([]string, 0, len(headers))
    for k := range headers {
        keys = append(keys, k)
    }
    sort.Strings(keys)
    var b strings.Builder
    for _, k := range keys {
        b.WriteString(k)
        b.WriteString("=")
        b.WriteString(headers[k])
    }
    return b.String()
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
	if r.Body == nil {
		return "", map[string]string{}, nil
	}
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
