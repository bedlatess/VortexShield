from __future__ import annotations

from html import escape

import secrets

from fastapi import APIRouter, Header, status
from fastapi.responses import HTMLResponse, JSONResponse

from app.core.config import get_settings
from app.schemas.captcha import (
    SiteAdminCreateData,
    SiteAdminCreateRequest,
    SiteAdminCreateResponse,
    SiteAdminData,
    SiteAdminListResponse,
)
from app.services.site_registry import SiteConfig, site_registry


router = APIRouter()
settings = get_settings()


@router.get("/home", response_class=HTMLResponse, include_in_schema=False)
def home_page() -> HTMLResponse:
    return HTMLResponse(_layout(title="VortexShield", body=_home_body(), active="home"))


@router.get("/home/api", response_class=HTMLResponse, include_in_schema=False)
def api_console_page() -> HTMLResponse:
    return HTMLResponse(_layout(title="VortexShield API Console", body=_api_console_body(), active="api"))


@router.get("/home/api/sites", response_model=SiteAdminListResponse)
def list_sites(
    x_vsec_admin_token: str = Header(default=""),
) -> SiteAdminListResponse | JSONResponse:
    if not _is_admin_authorized(x_vsec_admin_token):
        return _admin_forbidden()
    return SiteAdminListResponse(data=[_site_to_admin_data(site) for site in site_registry.list_sites()])


@router.post("/home/api/sites", response_model=SiteAdminCreateResponse)
def create_site(request: SiteAdminCreateRequest) -> SiteAdminCreateResponse | JSONResponse:
    if not _is_admin_authorized(request.admin_token):
        return _admin_forbidden()

    try:
        site, secret = site_registry.create_site(
            allowed_domains=request.allowed_domains,
            allowed_actions=request.allowed_actions,
        )
    except ValueError as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": 400, "msg": str(exc), "data": None},
        )

    return SiteAdminCreateResponse(
        data=SiteAdminCreateData(
            **_site_to_admin_data(site).model_dump(),
            secret=secret,
        )
    )


def _is_admin_authorized(token: str | None) -> bool:
    return secrets.compare_digest(str(token or ""), settings.admin_console_token)


def _admin_forbidden() -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"code": 403, "msg": "admin_token_required", "data": None},
    )


def _site_to_admin_data(site: SiteConfig) -> SiteAdminData:
    return SiteAdminData(
        site_key=site.site_key,
        allowed_domains=list(site.allowed_domains),
        allowed_actions=list(site.allowed_actions),
        enabled=site.enabled,
        created_at=site.created_at,
    )


def _layout(*, title: str, body: str, active: str) -> str:
    nav_home = "is-active" if active == "home" else ""
    nav_api = "is-active" if active == "api" else ""
    return f"""<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{escape(title)}</title>
    <style>
      :root {{
        color-scheme: light;
        --ink: #16211c;
        --muted: #66786e;
        --line: rgba(28, 49, 38, 0.14);
        --soft: #f4f7f2;
        --panel: rgba(255, 255, 255, 0.9);
        --green: #12845a;
        --green-2: #50c878;
        --blue: #245ed8;
        --amber: #c9932f;
        --red: #c9483d;
        --shadow: 0 22px 60px rgba(20, 35, 26, 0.12);
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        min-height: 100vh;
        color: var(--ink);
        font-family: "Segoe UI Variable", "Microsoft YaHei", "PingFang SC", sans-serif;
        background:
          linear-gradient(130deg, rgba(18, 132, 90, 0.13), transparent 38%),
          linear-gradient(35deg, rgba(201, 147, 47, 0.08), transparent 34%),
          #f8faf5;
      }}
      body::before {{
        content: "";
        position: fixed;
        inset: 0;
        pointer-events: none;
        background:
          linear-gradient(90deg, rgba(22, 34, 28, 0.034) 1px, transparent 1px),
          linear-gradient(rgba(22, 34, 28, 0.026) 1px, transparent 1px);
        background-size: 40px 40px;
        mask-image: radial-gradient(circle at 52% 28%, black, transparent 76%);
      }}
      .shell {{
        width: min(1120px, calc(100% - 32px));
        margin: 0 auto;
        position: relative;
        z-index: 1;
      }}
      header {{
        min-height: 72px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 18px;
      }}
      .brand {{
        display: flex;
        align-items: center;
        gap: 12px;
        color: inherit;
        text-decoration: none;
        font-weight: 900;
      }}
      .brand-mark {{
        width: 38px;
        height: 38px;
        display: grid;
        place-items: center;
        border-radius: 8px;
        background: linear-gradient(135deg, var(--green), var(--blue));
        color: white;
        box-shadow: 0 12px 30px rgba(22, 163, 106, 0.22);
      }}
      nav {{
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
      }}
      nav a {{
        min-height: 38px;
        display: inline-flex;
        align-items: center;
        padding: 0 13px;
        border-radius: 8px;
        color: #42534a;
        text-decoration: none;
        border: 1px solid transparent;
        font-size: 14px;
        font-weight: 750;
      }}
      nav a.is-active, nav a:hover {{
        border-color: var(--line);
        background: rgba(255, 255, 255, 0.7);
        color: var(--ink);
      }}
      main {{ padding: 34px 0 58px; }}
      .hero {{
        min-height: calc(100vh - 172px);
        display: grid;
        grid-template-columns: minmax(0, 1fr) 430px;
        gap: 36px;
        align-items: center;
      }}
      .eyebrow {{
        margin: 0 0 14px;
        color: var(--green);
        font-size: 13px;
        font-weight: 900;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }}
      h1 {{
        margin: 0;
        max-width: 820px;
        font-size: clamp(40px, 6.4vw, 76px);
        line-height: 1.02;
        letter-spacing: 0;
      }}
      .lead {{
        max-width: 700px;
        margin: 22px 0 0;
        color: var(--muted);
        font-size: 17px;
        line-height: 1.74;
      }}
      .actions {{
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        margin-top: 28px;
      }}
      .button {{
        min-height: 44px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        padding: 0 18px;
        border-radius: 8px;
        border: 1px solid var(--line);
        background: white;
        color: var(--ink);
        text-decoration: none;
        font-weight: 850;
        cursor: pointer;
      }}
      .button.primary {{
        border-color: transparent;
        color: white;
        background: linear-gradient(135deg, var(--green), #1ab56f);
        box-shadow: 0 18px 38px rgba(22, 163, 106, 0.22);
      }}
      .panel {{
        border: 1px solid var(--line);
        border-radius: 8px;
        background: var(--panel);
        box-shadow: var(--shadow);
        backdrop-filter: blur(16px);
      }}
      .metric-panel {{ padding: 18px; }}
      .command-panel {{
        padding: 18px;
        display: grid;
        gap: 14px;
      }}
      .command-top {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
      }}
      .status-pill {{
        min-height: 28px;
        display: inline-flex;
        align-items: center;
        gap: 7px;
        padding: 0 10px;
        border: 1px solid rgba(18, 132, 90, 0.18);
        border-radius: 999px;
        color: #0c6a47;
        background: #edf8f0;
        font-size: 12px;
        font-weight: 900;
      }}
      .status-dot {{
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: var(--green-2);
        box-shadow: 0 0 0 4px rgba(80, 200, 120, 0.14);
      }}
      .flow-step {{
        padding: 14px;
        border: 1px solid var(--line);
        border-radius: 8px;
        background: rgba(255, 255, 255, 0.72);
      }}
      .flow-step strong {{
        display: flex;
        justify-content: space-between;
        gap: 8px;
        margin-bottom: 6px;
      }}
      .flow-step span {{ color: var(--muted); font-size: 13px; line-height: 1.5; }}
      .metric {{
        display: grid;
        grid-template-columns: 46px 1fr;
        gap: 12px;
        padding: 15px 0;
        border-bottom: 1px solid var(--line);
      }}
      .metric:last-child {{ border-bottom: 0; }}
      .metric b {{
        display: grid;
        place-items: center;
        width: 46px;
        height: 46px;
        border-radius: 8px;
        color: white;
        background: linear-gradient(135deg, var(--green), var(--blue));
      }}
      .metric strong {{ display: block; margin-bottom: 5px; }}
      .metric span {{ color: var(--muted); font-size: 13px; line-height: 1.5; }}
      .grid {{
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 14px;
        margin-top: 24px;
      }}
      .card {{
        padding: 18px;
        border: 1px solid var(--line);
        border-radius: 8px;
        background: rgba(255, 255, 255, 0.74);
      }}
      .card h3 {{ margin: 0 0 8px; font-size: 17px; }}
      .card p {{ margin: 0; color: var(--muted); line-height: 1.6; font-size: 14px; }}
      .console {{
        display: grid;
        grid-template-columns: 400px minmax(0, 1fr);
        gap: 18px;
        align-items: start;
      }}
      .console .panel {{ padding: 18px; }}
      .console h1 {{
        font-size: clamp(30px, 4vw, 52px);
        margin-bottom: 12px;
      }}
      label {{
        display: grid;
        gap: 7px;
        margin-top: 14px;
        color: #314137;
        font-size: 13px;
        font-weight: 800;
      }}
      input, textarea {{
        width: 100%;
        border: 1px solid var(--line);
        border-radius: 8px;
        padding: 11px 12px;
        background: white;
        color: var(--ink);
        font: inherit;
        outline: none;
      }}
      textarea {{ min-height: 86px; resize: vertical; }}
      input:focus, textarea:focus {{
        border-color: rgba(22, 163, 106, 0.45);
        box-shadow: 0 0 0 3px rgba(22, 163, 106, 0.12);
      }}
      .notice {{
        min-height: 22px;
        margin: 12px 0 0;
        color: var(--muted);
        font-size: 13px;
        line-height: 1.5;
      }}
      .notice.ok {{ color: var(--green); }}
      .notice.error {{ color: var(--red); font-weight: 800; }}
      .table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
      }}
      .table-wrap {{
        width: 100%;
        overflow-x: auto;
      }}
      .table th, .table td {{
        padding: 12px 10px;
        border-bottom: 1px solid var(--line);
        text-align: left;
        vertical-align: top;
      }}
      .table th {{ color: #32443a; font-size: 12px; }}
      code {{
        padding: 2px 6px;
        border-radius: 6px;
        background: #edf5ec;
        color: #146947;
        overflow-wrap: anywhere;
      }}
      .secret-box {{
        display: none;
        margin-top: 14px;
        padding: 14px;
        border-radius: 8px;
        border: 1px solid rgba(22, 163, 106, 0.24);
        background: #f0faf3;
      }}
      .secret-box.is-visible {{ display: block; }}
      .muted {{ color: var(--muted); }}
      .section-title {{
        margin: 0 0 10px;
        font-size: 14px;
        color: var(--muted);
        font-weight: 900;
        letter-spacing: 0.05em;
        text-transform: uppercase;
      }}
      @media (max-width: 860px) {{
        header {{ align-items: flex-start; flex-direction: column; padding-top: 18px; }}
        .hero, .console {{ grid-template-columns: 1fr; }}
        .grid {{ grid-template-columns: 1fr; }}
        h1 {{ font-size: clamp(34px, 12vw, 52px); }}
        .lead {{ font-size: 16px; }}
        .command-panel {{ padding: 14px; }}
      }}
    </style>
  </head>
  <body>
    <div class="shell">
      <header>
        <a class="brand" href="/home"><span class="brand-mark">VS</span><span>VortexShield</span></a>
        <nav>
          <a class="{nav_home}" href="/home">首页</a>
          <a class="{nav_api}" href="/home/api">接入控制台</a>
          <a href="/docs">接口文档</a>
        </nav>
      </header>
      <main>{body}</main>
    </div>
  </body>
</html>"""


def _home_body() -> str:
    return """
<section class="hero">
  <div>
    <p class="eyebrow">Adaptive Trust Gateway</p>
    <h1>把人机验证升级为业务可信入口</h1>
    <p class="lead">
      VortexShield 面向登录、注册、支付和内容发布场景，提供无感优先的安全校验编排。
      系统会根据环境指纹、行为轨迹和站点策略自动决定通过、轻交互确认或滑块校验。
    </p>
    <div class="actions">
      <a class="button primary" href="/home/api">创建接入凭证</a>
      <a class="button" href="/docs">查看接口</a>
    </div>
    <div class="grid">
      <article class="card"><h3>可信评分</h3><p>低风险访问自动放行，异常访问进入更强校验流程。</p></article>
      <article class="card"><h3>密文轨迹</h3><p>RSA-OAEP 封装 AES-GCM 会话密钥，轨迹和指纹全程认证加密。</p></article>
      <article class="card"><h3>站点凭证</h3><p>没有后台创建的 siteKey 和 secret，SDK 与 siteverify 都无法完成验证。</p></article>
    </div>
  </div>
  <aside class="panel command-panel">
    <div class="command-top">
      <strong>风控决策链路</strong>
      <span class="status-pill"><i class="status-dot"></i>ACTIVE</span>
    </div>
    <div class="flow-step"><strong>01 静默预检 <em>SILENT</em></strong><span>可信环境直接签发短时安全凭证，用户无感通过。</span></div>
    <div class="flow-step"><strong>02 轻量确认 <em>CHECKBOX</em></strong><span>弱信号场景触发低摩擦交互，继续采集行为轨迹。</span></div>
    <div class="flow-step"><strong>03 精准校验 <em>SLIDER</em></strong><span>高风险访问进入滑块拼合与轨迹动力学双重校验。</span></div>
    <div class="flow-step"><strong>04 服务端验签 <em>SITEVERIFY</em></strong><span>业务后端使用私有 secret 一次性消费安全签名。</span></div>
  </aside>
</section>
"""


def _api_console_body() -> str:
    return """
<section class="console">
  <div class="panel">
    <p class="section-title">Access Provisioning</p>
    <h1>接入凭证中心</h1>
    <p class="muted">为业务站点创建专属 siteKey / secret。secret 只在创建时展示一次，请保存在业务后端。</p>
    <form id="site-form">
      <label>
        后台令牌
        <input id="admin-token" type="password" placeholder="VSEC_ADMIN_TOKEN" autocomplete="off" />
      </label>
      <label>
        允许域名
        <textarea id="domains" placeholder="example.com&#10;login.example.com">localhost
127.0.0.1</textarea>
      </label>
      <label>
        允许动作
        <input id="actions" value="login,signup,checkout" />
      </label>
      <button class="button primary" type="submit">签发接入凭证</button>
      <p class="notice" id="notice">输入后台令牌后即可签发站点凭证。</p>
    </form>
    <div class="secret-box" id="secret-box"></div>
  </div>
  <div class="panel">
    <p class="section-title">Configured Properties</p>
    <h1>站点资产</h1>
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr><th>siteKey</th><th>域名</th><th>动作</th><th>状态</th></tr>
        </thead>
        <tbody id="sites-body"></tbody>
      </table>
    </div>
  </div>
</section>
<script>
  const form = document.querySelector("#site-form");
  const adminTokenInput = document.querySelector("#admin-token");
  const domainsInput = document.querySelector("#domains");
  const actionsInput = document.querySelector("#actions");
  const notice = document.querySelector("#notice");
  const tableBody = document.querySelector("#sites-body");
  const secretBox = document.querySelector("#secret-box");

  loadSites();

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    notice.className = "notice";
    notice.textContent = "正在签发接入凭证...";
    secretBox.classList.remove("is-visible");
    const payload = {
      allowed_domains: domainsInput.value.split(/\\n|,/).map((item) => item.trim()).filter(Boolean),
      allowed_actions: actionsInput.value.split(",").map((item) => item.trim()).filter(Boolean),
      admin_token: adminTokenInput.value.trim(),
    };
    try {
      const response = await fetch("/home/api/sites", {
        method: "POST",
        headers: {"Content-Type": "application/json", "Accept": "application/json"},
        body: JSON.stringify(payload),
      });
      const body = await response.json();
      if (!response.ok || body.code !== 200) {
        throw new Error(body.msg || `HTTP ${response.status}`);
      }
      window.localStorage.setItem("vsec_admin_token", payload.admin_token);
      notice.className = "notice ok";
      notice.textContent = "接入凭证签发成功。";
      secretBox.innerHTML = `
        <strong>请立刻保存私有 secret</strong>
        <p class="muted">siteKey 放在前端，secret 只能放在业务后端。</p>
        <p><code>${escapeHTML(body.data.site_key)}</code></p>
        <p><code>${escapeHTML(body.data.secret)}</code></p>
      `;
      secretBox.classList.add("is-visible");
      await loadSites();
    } catch (error) {
      notice.className = "notice error";
      notice.textContent = error instanceof Error ? error.message : String(error);
    }
  });

  async function loadSites() {
    const token = window.localStorage.getItem("vsec_admin_token") || "";
    const response = await fetch("/home/api/sites", {
      headers: {"Accept": "application/json", "X-VSEC-Admin-Token": token}
    });
    const body = await response.json();
    if (!response.ok || body.code !== 200) {
      tableBody.innerHTML = `<tr><td colspan="4" class="muted">输入后台令牌后可查看已配置站点。</td></tr>`;
      return;
    }
    tableBody.innerHTML = (body.data || []).map((site) => `
      <tr>
        <td><code>${escapeHTML(site.site_key)}</code></td>
        <td>${escapeHTML(site.allowed_domains.join(", "))}</td>
        <td>${escapeHTML(site.allowed_actions.join(", "))}</td>
        <td>${site.enabled ? "启用" : "停用"}</td>
      </tr>
    `).join("");
  }

  function escapeHTML(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
</script>
"""
