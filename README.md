# OPEN API Golang 签名 SDK

## 签名算法说明

### 公共参数

| 参数             | 说明                  |
| -------------- | ------------------- |
| AccessKey (AK) | 平台分配的访问密钥           |
| SecretKey (SK) | 平台分配的签名密钥，不可泄露      |
| Timestamp      | Unix 时间戳（秒），用于防重放攻击 |

### HTTP 请求头

| Header         | 说明          |
| -------------- | ----------- |
| `PG-Timestamp` | Unix 时间戳（秒） |
| `PG-AccessKey` | 访问密钥 AK     |
| `PG-Sign`      | 请求/响应签名值    |

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

**Step 3：构造最终签名串**

```
finalText = URL路径 + 参数签名串 + Timestamp + SecretKey
```

**Step 4：计算签名**

```
Sign = SHA256(finalText)  // 十六进制小写字符串
```

**Step 5：设置请求头**

```
PG-Timestamp: <timestamp>
PG-AccessKey: <ak>
PG-Sign: <sign>
```

### 示例一：application/x-www-form-urlencoded

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

**Step 3** 构造最终签名串：

```
finalText = "/v1/photos/generate" + "a=bd=cdata=a" + "1712563200" + "sk"
          = "/v1/photos/generatea=bd=cdata=a1712563200sk"
```

**Step 4** 计算签名：

```
Sign = SHA256("/v1/photos/generatea=bd=cdata=a1712563200sk")
     = "2860729940c7ea4b9caa722b5ec28bcf3d41e11a3487d68d8662aac397d361ea"
```

***

### 示例二：application/json

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

**Step 3** 构造最终签名串：

```
finalText = "/v1/photos/list" + "page=2zone=cn{\"title\":\"测试\",\"type\":1}" + "1712563200" + "sk"
          = "/v1/photos/listpage=2zone=cn{\"title\":\"测试\",\"type\":1}1712563200sk"
```

**Step 4** 计算签名：

```
Sign = SHA256("/v1/photos/listpage=2zone=cn{\"title\":\"测试\",\"type\":1}1712563200sk")
     = "64c73268fecb39f3c3d04a9831d9272ff206dcf68f24fa2cfc0163eeab6680f9"
```

***

## 二、请求签名验证算法

服务端收到请求后按以下步骤验证：

**Step 1：** 从请求头读取 `PG-Timestamp`，验证时间戳是否在有效期内（默认 3600 秒）：

```
if now() - PG-Timestamp > expiredIn → 返回错误：timestamp expired
```

**Step 2：** 按照与客户端相同的方式，从请求中提取参数，构造 `finalText`。

**Step 3：** 计算 `SHA256(finalText)`，与请求头中的 `PG-Sign` 比对：

```
if SHA256(finalText) == PG-Sign → 验证通过
else → 返回错误：signature validation failed
```

***

## 三、响应签名算法

服务端对响应体进行签名，步骤如下：

**Step 1：** 获取当前 Unix 时间戳 `ts`。

**Step 2：** 构造最终签名串（响应无 Query/Form 参数，参数签名串为空）：

```
finalText = URL路径 + "" + Body原文 + ts + SecretKey
          = URL路径 + Body原文 + ts + SecretKey
```

**Step 3：** 计算签名：

```
Sign = SHA256(finalText)
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
finalText = "/v1/photos/generate" + "aaaaaaa" + "1712563200" + "sk"
          = "/v1/photos/generateaaaaaaa1712563200sk"
```

**Step 3** 计算签名：

```
Sign = SHA256("/v1/photos/generateaaaaaaa1712563200sk")
     = "03c102a51a81f2ae5f165fe3296079d7ab942f92dd7bd4b70e5e10a747ea1cf0"
```

***

## 四、响应签名验证算法

客户端收到响应后按以下步骤验证：

**Step 1：** 从响应头读取 `PG-Timestamp`、`PG-AccessKey`、`PG-Sign`，任一缺失则返回错误。

**Step 2：** 验证 `PG-AccessKey` 与本地 AK 一致。

**Step 3：** 读取响应 Body，按照与服务端相同的方式构造 `finalText`：

```
finalText = URL路径 + Body原文 + PG-Timestamp + SecretKey
```

**Step 4：** 计算 `SHA256(finalText)`，与响应头中的 `PG-Sign` 比对：

```
if SHA256(finalText) == PG-Sign → 验证通过
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

// 请求签名
func signRequest(path, params, body, ts, sk) string:
    finalText = path + buildParamsSignatureText(params, body) + ts + sk
    return SHA256(finalText)

// 响应签名
func signResponse(path, body, ts, sk) string:
    finalText = path + body + ts + sk
    return SHA256(finalText)
```

