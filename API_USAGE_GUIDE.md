# VortexShield 接入凭证与 API 使用指南

本文档面向两类角色：

- **VortexShield 管理员**：负责创建、停用、删除站点 API，并轮换私有 `secret`。
- **业务系统开发者**：负责把 VortexShield SDK 接入网站前端，并在业务后端调用 `/api/siteverify` 完成验签。

## 1. 访问入口

线上服务地址：

```text
https://vsec.pawn.eu.org
```

产品首页：

```text
https://vsec.pawn.eu.org/home
```

接入凭证中心：

```text
https://vsec.pawn.eu.org/home/api
```

项目管理员后台：

```text
https://vsec.pawn.eu.org/home/admin/login
```

接口文档：

```text
https://vsec.pawn.eu.org/docs
```

## 2. 管理员令牌

管理员令牌由部署环境变量 `VSEC_ADMIN_TOKEN` 控制。

Docker Compose 示例：

```yaml
environment:
  PYTHONDONTWRITEBYTECODE: "1"
  PYTHONUNBUFFERED: "1"
  VSEC_SITE_REGISTRY_PATH: "/app/data/site_registry.json"
  VSEC_ADMIN_TOKEN: "your-long-random-admin-token"
```

修改后重启：

```bash
docker compose up -d
docker compose exec vsec-api printenv VSEC_ADMIN_TOKEN
```

注意：

- `/home/admin/login` 只给 VortexShield 项目管理员使用。
- `/home/api` 是接入凭证中心，用于签发业务站点的 `siteKey` 和 `secret`。
- 生产环境建议在 Nginx Proxy Manager、WAF 或防火墙层限制 `/home/admin` 来源 IP。

## 3. 创建接入凭证

进入：

```text
https://vsec.pawn.eu.org/home/api
```

填写：

- **控制台令牌**：`VSEC_ADMIN_TOKEN`
- **允许域名**：允许调用 VortexShield 的业务域名，例如 `example.com`
- **允许动作**：业务动作，例如 `login,signup,checkout`

创建成功后会得到：

```text
siteKey = vsec_site_xxx
secret  = vsec_secret_xxx
```

保存规则：

- `siteKey` 是公开值，可以放在前端。
- `secret` 是私有值，只能放在业务后端。
- `secret` 只在创建或轮换时展示一次。
- 如果没有有效 `siteKey`，前端即使加载 SDK 也会收到 `invalid_site_key`。

## 4. 前端 SDK 接入

把编译后的 SDK 文件部署到业务站点，例如：

```text
/vsec-sdk.js
```

页面中加入容器：

```html
<div id="vsec-captcha"></div>
<input type="hidden" id="vsec_signature" name="vsec_signature" />
```

加载并执行 SDK：

```html
<script src="/vsec-sdk.js"></script>
<script>
  const captcha = new window.CaptchaSDK({
    container: "#vsec-captcha",
    apiBaseUrl: "https://vsec.pawn.eu.org",
    siteKey: "vsec_site_xxx",
    action: "login",
    onSuccess(signature) {
      document.querySelector("#vsec_signature").value = signature;
    },
    onFailure(reason) {
      console.warn("VortexShield verification failed:", reason);
    },
    onError(error) {
      console.error("VortexShield SDK error:", error);
    },
  });

  captcha.execute();
</script>
```

参数说明：

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `container` | 是 | SDK 挂载容器，可以是 CSS 选择器或 HTMLElement |
| `apiBaseUrl` | 是 | VortexShield 服务地址 |
| `siteKey` | 是 | 接入凭证中心签发的公开站点 key |
| `action` | 否 | 业务动作，默认 `login`，必须在允许动作列表中 |
| `onSuccess` | 否 | 验证成功回调，返回 `verify_signature` |
| `onFailure` | 否 | 验证失败回调 |
| `onError` | 否 | SDK 异常回调 |

## 5. 业务后端验签

前端拿到的 `verify_signature` 不能直接信任。业务后端必须使用私有 `secret` 调用：

```text
POST /api/siteverify
```

请求示例：

```bash
curl -X POST https://vsec.pawn.eu.org/api/siteverify \
  -H "Content-Type: application/json" \
  -d '{
    "secret": "vsec_secret_xxx",
    "response": "vsig_xxx",
    "action": "login",
    "hostname": "example.com"
  }'
```

成功响应：

```json
{
  "success": true,
  "score": 0.12,
  "action": "login",
  "hostname": "example.com",
  "challenge_ts": "2026-06-05T10:00:00+00:00",
  "error_codes": []
}
```

失败响应：

```json
{
  "success": false,
  "score": null,
  "action": null,
  "hostname": null,
  "challenge_ts": null,
  "error_codes": ["invalid-or-timeout-response"]
}
```

验签规则：

- `response` 是一次性凭证，成功或失败消费后都不可复用。
- `secret` 必须匹配创建该 `siteKey` 时生成的私有密钥。
- 如果传入 `action`，必须与前端 SDK 中的 `action` 一致。
- 如果传入 `hostname`，必须与 SDK 采集的浏览器域名一致。

## 6. 管理员后台能力

进入：

```text
https://vsec.pawn.eu.org/home/admin/login
```

使用 `VSEC_ADMIN_TOKEN` 登录后，可以：

- 查看全部站点 API。
- 启用或停用某个 `siteKey`。
- 删除自定义站点 API。
- 轮换私有 `secret`。
- 查看当前运行态信息，例如 Session Backend、注册表路径和管理员 Cookie 名称。

说明：

- 内置 demo 站点受保护，删除会返回 `demo_site_cannot_be_deleted`。
- 停用站点后，该站点的 SDK 会收到 `site_disabled`。
- 轮换 `secret` 后，旧 secret 立即失效。

## 7. 常见错误码

| 错误码 | 含义 | 处理方式 |
| --- | --- | --- |
| `invalid_site_key` | siteKey 不存在 | 在 `/home/api` 创建或检查前端配置 |
| `site_disabled` | siteKey 已停用 | 在管理员后台启用 |
| `hostname_not_allowed` | 当前域名不在允许域名内 | 创建新凭证或更新站点配置 |
| `action_not_allowed` | action 不在允许动作内 | 修改 SDK action 或重新签发凭证 |
| `admin_token_required` | 管理员令牌缺失或错误 | 检查 `VSEC_ADMIN_TOKEN` |
| `invalid-input-secret` | siteverify secret 错误 | 检查业务后端 secret |
| `invalid-or-timeout-response` | verify_signature 无效、过期或已消费 | 重新执行前端验证 |
| `action-mismatch` | siteverify action 不匹配 | 保持前端 action 与后端校验一致 |
| `hostname-mismatch` | siteverify hostname 不匹配 | 检查业务域名和传参 |

## 8. 最小业务后端示例

Python 示例：

```python
import requests


def verify_vortexshield(signature: str) -> bool:
    response = requests.post(
        "https://vsec.pawn.eu.org/api/siteverify",
        json={
            "secret": "vsec_secret_xxx",
            "response": signature,
            "action": "login",
            "hostname": "example.com",
        },
        timeout=5,
    )
    data = response.json()
    return bool(data.get("success"))
```

Node.js 示例：

```js
async function verifyVortexShield(signature) {
  const response = await fetch("https://vsec.pawn.eu.org/api/siteverify", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      secret: "vsec_secret_xxx",
      response: signature,
      action: "login",
      hostname: "example.com",
    }),
  });
  const data = await response.json();
  return Boolean(data.success);
}
```

## 9. 部署数据位置

当前站点凭证注册表保存到：

```text
data/site_registry.json
```

Docker Compose 已挂载：

```yaml
volumes:
  - ./data:/app/data
```

因此容器重启后，已创建的站点 API 不会丢失。

生产集群化时，建议把以下组件迁移到 Redis 或数据库：

- `site_registry.py` 站点注册表
- captcha session
- precheck RSA 私钥 session
- verify signature session
- verify rate limit bucket

