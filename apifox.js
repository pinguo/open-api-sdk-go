
class SignatureBuilder {
    constructor(accessKey, secretKey, expiredIn) {
        this.accessKey = accessKey;
        this.secretKey = secretKey;
        this.expiredIn = expiredIn;
    }

    // HMAC-SHA256 with SK as key, hex lowercase
    hash(text) {
        return CryptoJS.HmacSHA256(text, this.secretKey).toString();
    }

    // params: flat key->value map; body: string (json raw or "")
    buildParamsSignatureText(params, body) {
        const keys = Object.keys(params || {}).sort();
        let paramStr = "";
        for (const k of keys) {
            paramStr += `${k}=${params[k]}`;
        }
        return paramStr + (body || "");
    }

    // Build header signature text: only PG-* except timestamp/accesskey/sign, keys lowercased and sorted
    buildHeaderSignatureText(headers) {
        if (!headers) return "";
        let list = [];
        try {
            if (typeof headers.all === 'function') list = headers.all();
            else if (Array.isArray(headers)) list = headers;
        } catch (_) { /* ignore */ }

        const excludes = new Set(["pg-timestamp", "pg-accesskey", "pg-sign"]);
        const picked = {};
        for (const h of list) {
            if (!h || !h.key) continue;
            const lower = String(h.key).toLowerCase();
            if (lower.startsWith("pg-") && !excludes.has(lower)) {
                if (picked[lower] === undefined) picked[lower] = h.value ?? ""; // first value
            }
        }
        const keys = Object.keys(picked).sort();
        if (keys.length === 0) return "";
        let out = "";
        for (const k of keys) out += `${k}=${picked[k]}`;
        return out;
    }

    // Normalize GET params from pm.request.url.query.all() or plain object
    // Spec requires: each key keeps the first value only (no arrays)
    getGETParams(params) {
        if (Array.isArray(params)) {
            const obj = {};
            params.forEach(item => {
                if (!item || item.disabled || !item.key) return;
                if (obj[item.key] === undefined) obj[item.key] = item.value ?? '';
            });
            return obj;
        }
        return params || {};
    }

    // Extract body and/or form params based on content type and body mode
    getPOSTParams(contentType, data) {
        const defaultContentType = "application/x-www-form-urlencoded";
        const ct = (contentType || '').toLowerCase() || defaultContentType;

        // application/json: body raw string participates; not parsed
        // Follow spec strictly: rely on Content-Type only
        if (ct.includes("application/json")) {
            let body = '';
            if (data) {
                if (typeof data.raw === 'string') body = data.raw;
                else if (typeof data === 'string') body = data;
            }
            return [body, null];
        }

        // application/x-www-form-urlencoded: parse k/v and merge into query params
        if (ct.includes(defaultContentType) || (data && data.mode === 'urlencoded')) {
            const params = {};
            // Prefer structured list if available (Postman/Apifox)
            const list = (data && data.urlencoded && typeof data.urlencoded.all === 'function')
                ? data.urlencoded.all()
                : (data && Array.isArray(data.urlencoded) ? data.urlencoded : []);
            if (list.length) {
                list.forEach(it => {
                    if (!it || it.disabled || !it.key) return;
                    if (params[it.key] === undefined) params[it.key] = it.value ?? '';
                });
                return ["", params];
            }
            // Fallback: parse raw body string like a=b&c=d
            let raw = '';
            if (typeof data === 'string') raw = data;
            else if (data && typeof data.raw === 'string') raw = data.raw;
            if (raw) {
                raw.split('&').forEach(pair => {
                    if (!pair) return;
                    const idx = pair.indexOf('=');
                    let k, v;
                    if (idx >= 0) {
                        k = pair.slice(0, idx);
                        v = pair.slice(idx + 1);
                    } else {
                        k = pair;
                        v = '';
                    }
                    try {
                        k = decodeURIComponent(k);
                    } catch (_) {}
                    try {
                        v = decodeURIComponent(v);
                    } catch (_) {}
                    if (k && params[k] === undefined) params[k] = v;
                });
            }
            return ["", params];
        }

        throw new Error("unsupported content type: " + ct);
    }

    // Main entry: build signature per Go SDK
    signRequest(url, method, headers, data, params) {
        // 1) query params
        let queryParams = this.getGETParams(params || {});

        // 2) content type detection
        let contentType = null;
        try {
            if (headers && typeof headers.get === 'function') {
                contentType = headers.get('Content-Type') || headers.get('content-type');
            }
        } catch (_) { /* ignore */ }
        if (!contentType && data && typeof data.type === 'string') {
            contentType = data.type;
        }

        // 3) body / post params
        const [body, postParams] = this.getPOSTParams(contentType, data || {});
        if (postParams) {
            queryParams = { ...queryParams, ...postParams };
        }

        // 4) timestamp
        const ts = Math.floor(Date.now() / 1000).toString();

        // 5) path
        const path = requestPath();

        // 6) header signature text from existing PG-* headers (excluding sign/auth headers)
        const headerText = this.buildHeaderSignatureText(headers);

        // 7) final text = METHOD + PATH + paramSig + headerSig + ts + AK
        const methodUpper = String(method || '').toUpperCase();
        const finalText = `${methodUpper}${path}${this.buildParamsSignatureText(queryParams, body)}${headerText}${ts}${this.accessKey}`;
        try { if (typeof console !== 'undefined' && console && console.log) console.log("finalText:" + finalText); } catch (_) {}
        const sign = this.hash(finalText);

        return { Sign: sign, FinalText: finalText, Timestamp: ts };
    }
}

function requestPath() {
    var parts = [];
    pm.request.url.path.map(v => {
        if (v.indexOf(":") === 0) {
            const find = pm.request.url.variables.find(item => item.key == v.slice(1))
            parts.push(find.value)
        } else {
            parts.push(v)
        }
    });
      
    if (parts.length > 0) {
        return "/" + parts.join("/")
    }
    return ""
}

ak = pm.environment.get("pg_ak");
sk = pm.environment.get("pg_sk");
const singer = new SignatureBuilder(ak, sk, 3600);
sr = singer.signRequest(pm.request.url.toString(), pm.request.method, pm.request.headers, pm.request.body, pm.request.url.query.all());

pm.request.headers.add({key: "PG-Sign", value: sr.Sign});
pm.request.headers.add({key: "PG-Timestamp", value: sr.Timestamp});
pm.request.headers.add({key: "PG-AccessKey", value: ak});

