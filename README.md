# OPEN API Golang 签名 SDK

## 签名算法说明

### 公共参数

| 参数             | 说明                  |
| -------------- | ------------------- |
| AccessKey (AK) | 平台分配的访问AccessKey           |
| SecretKey (SK) | 平台分配的签名SecretKey，不可泄露      |
| Timestamp      | Unix 时间戳（秒），用于防重放攻击 |

### HTTP 请求头

| Header         | 说明          |
| -------------- | ----------- |
| `PG-Timestamp` | Unix 时间戳（秒） |
| `PG-AccessKey` | 访问密钥 AK     |
| `PG-Sign`      | 请求/响应签名值    |
| `PG-*`         | 以 `PG-` 开头的自定义头参与构造header签名串（除上述三者外，这三个会直接在签名串中参与）|

***

## 一、请求签名算法

### 计算步骤

**Step 1：收集参数**

- Query 参数：从 URL Query String 中提取所有键值对，**每个 key 只取第一个值，不支持数组参数**（如 `ids=1&ids=2` 只取 `ids=1`）
- Body 参数（根据 Content-Type 处理）：
  - `application/json`：Body 原文字符串直接参与签名，不解析为键值对
  - `application/x-www-form-urlencoded`：解析为键值对，与 Query 参数合并，同样**每个 key 只取第一个值**

**Step 2：构造参数签名串**

将所有参数（Query 参数 + Form 参数）的 key 按字典序升序排列，拼接为：

```
key1=value1key2=value2...keyN=valueN
```

若 Content-Type 为 `application/json`，则在参数串末尾追加 Body 原文：

```
key1=value1key2=value2...{json body}
```

**Step 3：构造 Header 签名串（仅请求）**

从请求头中筛选参与签名的 Header：

- 仅保留以 `PG-` 开头的 Header；
- 排除 `PG-Timestamp`、`PG-AccessKey`、`PG-Sign`；
- 将 Header Key 全部转为小写；
- 按字典序升序排列后按 `key=value` 连续拼接，无分隔符。

若没有符合条件的 Header，则该部分为空串。

示例：`PG-Client: ios` 与 `PG-Trace-Id: abc` → `pg-client=iospg-trace-id=abc`

**Step 4：构造最终签名串（请求）**

```
finalText = HTTP方法 + URL路径 + 参数签名串 + Header签名串 + Timestamp + AccessKey
```

**Step 5：计算签名（HMAC-SHA256）**

```
// data = finalText, key = SecretKey
Sign = HMAC_SHA256(finalText, SecretKey)  // 十六进制小写
```

**Step 6：设置请求头**

```
PG-Timestamp: <timestamp>
PG-AccessKey: <ak>
PG-Sign: <sign>
```

### 示例一：application/x-www-form-urlencoded（无 PG-* 业务头）

**请求信息：**

```
POST /v1/photos/generate?data=a
Content-Type: application/x-www-form-urlencoded

a=b&d=c
```

**参数：** AK = `ak`，SK = `sk`，Timestamp = `1712563200`

**Step 1** 收集并合并参数：

```
Query 参数: data=a
Form  参数: a=b, d=c
合并后所有 key: [a, d, data]
```

**Step 2** 按字典序排序 key（a < d < data），拼接参数签名串：

```
排序前: data=a, a=b, d=c   ← 原始顺序（无序）
排序后: a=b,   d=c, data=a ← 字典序升序

参数签名串 = "a=b" + "d=c" + "data=a" = "a=bd=cdata=a"
```

**Step 3-4** Header 签名串为空；构造最终签名串（方法为 POST）：

```
finalText = "POST" + "/v1/photos/generate" + "a=bd=cdata=a" + "" + "1712563200" + "ak"
          = "POST/v1/photos/generatea=bd=cdata=a1712563200ak"
```

**Step 5** 计算签名（HMAC-SHA256，key=sk）：

```
Sign = HMAC_SHA256("POST/v1/photos/generatea=bd=cdata=a1712563200ak", "sk")
     = "57f4761dbdaf2cd2624f6e88bdcc97416937f9c6a0e0874ea534915d3ade0556"
```

***

### 示例二：application/json（无 PG-* 业务头）

**请求信息：**

```
POST /v1/photos/list?zone=cn&page=2
Content-Type: application/json

{"title":"测试","type":1}
```

**参数：** AK = `ak`，SK = `sk`，Timestamp = `1712563200`

**Step 1** 收集参数（JSON Body 不解析为键值对，整体作为 body 字符串）：

```
Query 参数: zone=cn, page=2
Body 原文:  {"title":"测试","type":1}
```

**Step 2** 仅对 Query 参数按字典序排序，拼接后追加 Body 原文：

```
排序前: zone=cn, page=2   ← 原始顺序（无序）
排序后: page=2,  zone=cn  ← 字典序升序（p < z）

参数签名串 = "page=2" + "zone=cn" + {"title":"测试","type":1}
           = "page=2zone=cn{\"title\":\"测试\",\"type\":1}"
```

**Step 3-4** Header 签名串为空；构造最终签名串（方法为 POST）：

```
finalText = "POST" + "/v1/photos/list" + "page=2zone=cn{\"title\":\"测试\",\"type\":1}" + "" + "1712563200" + "ak"
          = "POST/v1/photos/listpage=2zone=cn{\"title\":\"测试\",\"type\":1}1712563200ak"
```

**Step 5** 计算签名（HMAC-SHA256，key=sk）：

```
Sign = HMAC_SHA256("POST/v1/photos/listpage=2zone=cn{\"title\":\"测试\",\"type\":1}1712563200ak", "sk")
     = "ea20e81a9fc109d9ffa96e7d43f5d28f6868ff93f2773ea1c2a78596e4c2a4cd"

### 示例三：包含 PG-* 业务头

```
POST /v1/test
PG-Client: ios
PG-Trace-Id: abc

<empty body>
```

Header 签名串：`pg-client=iospg-trace-id=abc`

```
finalText = "GET" + "/v1/test" + "" + "pg-client=iospg-trace-id=abc" + "1712563200" + "ak"
Sign = HMAC_SHA256(finalText, "sk")
     = "b55aae13568afb2c32b2b05794184c251cfed83ecd17b83dcd9cb0c16e2eea6e"
```
```

***

## 二、请求签名验证算法

服务端收到请求后按以下步骤验证：

**Step 1：** 从请求头读取 `PG-Timestamp`，验证时间戳是否在有效期内（默认 3600 秒）：

```
if now() - PG-Timestamp > expiredIn → 返回错误：timestamp expired
```

**Step 2：** 按照与客户端相同的方式，从请求中提取参数，构造 `finalText`。

**Step 3：** 计算 `HMAC_SHA256(finalText, SecretKey)`，与请求头中的 `PG-Sign` 比对：

```
if HMAC_SHA256(finalText, SecretKey) == PG-Sign → 验证通过
else → 返回错误：signature validation failed
```

***

## 三、响应签名算法

服务端对响应体进行签名，步骤如下：

**Step 1：** 获取当前 Unix 时间戳 `ts`。

**Step 2：** 构造最终签名串（响应无 Query/Form 参数与 Header 签名串）：

```
finalText = URL路径 + Body原文 + ts + AccessKey
```

**Step 3：** 计算签名（HMAC-SHA256）：

```
Sign = HMAC_SHA256(finalText, SecretKey)
```

**Step 4：** 在响应头中设置：

```
PG-Timestamp: <ts>
PG-AccessKey: <ak>
PG-Sign: <sign>
```

### 响应签名示例

**响应信息：**

```
GET /v1/photos/generate
Response Body: aaaaaaa
```

**参数：** AK = `ak`，SK = `sk`，Timestamp = `1712563200`

**Step 2** 构造最终签名串：

```
finalText = "/v1/photos/generate" + "aaaaaaa" + "1712563200" + "ak"
          = "/v1/photos/generateaaaaaaa1712563200ak"
```

**Step 3** 计算签名（HMAC-SHA256，key=sk）：

```
Sign = HMAC_SHA256("/v1/photos/generateaaaaaaa1712563200ak", "sk")
     = "46acb18dd316b06a50a28e1110c6fa573994a320920bf47804a6d79a104882bc"
```

***

## 四、响应签名验证算法

客户端收到响应后按以下步骤验证：

**Step 1：** 从响应头读取 `PG-Timestamp`、`PG-AccessKey`、`PG-Sign`，任一缺失则返回错误。

**Step 2：** 验证 `PG-AccessKey` 与本地 AK 一致。

**Step 3：** 读取响应 Body，按照与服务端相同的方式构造 `finalText`：

```
finalText = URL路径 + Body原文 + PG-Timestamp + AccessKey
```

**Step 4：** 计算 `HMAC_SHA256(finalText, SecretKey)`，与响应头中的 `PG-Sign` 比对：

```
if HMAC_SHA256(finalText, SecretKey) == PG-Sign → 验证通过
else → 返回错误：signature validation failed
```

***

## 五、签名算法伪代码汇总

```
// 参数签名串构造
func buildParamsSignatureText(params map[string]string, body string) string:
    keys = sort(params.keys())
    paramStr = ""
    for k in keys:
        paramStr += k + "=" + params[k]
    return paramStr + body

// Header 签名串构造（请求）
func buildHeaderSignatureText(headers map[string]string) string:
    pick only keys with prefix "pg-" except pg-timestamp, pg-accesskey, pg-sign
    lower-case keys; sort; then concat as key=value without separator

// 请求签名（HMAC-SHA256）
func signRequest(path, params, headers, body, ts, ak, sk) string:
    finalText = path + buildParamsSignatureText(params, body) + buildHeaderSignatureText(headers) + ts + ak
    return HMAC_SHA256(finalText, sk)

// 响应签名（HMAC-SHA256）
func signResponse(path, body, ts, ak, sk) string:
    finalText = path + body + ts + ak
    return HMAC_SHA256(finalText, sk)

// HMAC-SHA256 参考实现
func Sha256(data string, key string) string:
    h = hmac.New(sha256.New, key)
    h.Write([]byte(data))
    return hex.EncodeToString(h.Sum(nil))
```
