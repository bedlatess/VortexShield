from __future__ import annotations

import secrets
import time
from html import escape

from fastapi import APIRouter, Header, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from app.core.config import get_settings
from app.schemas.captcha import (
    AdminLoginRequest,
    AdminLoginResponse,
    AdminSecretRotateData,
    AdminSecretRotateResponse,
    AdminSiteMutationResponse,
    AdminStatsData,
    AdminStatsResponse,
    SiteAdminCreateData,
    SiteAdminCreateRequest,
    SiteAdminCreateResponse,
    SiteAdminData,
    SiteAdminListResponse,
)
from app.services.site_registry import SiteConfig, site_registry


router = APIRouter()
settings = get_settings()

ADMIN_COOKIE_NAME = "vsec_admin_session"
ADMIN_SESSION_TTL_SECONDS = 7200
_admin_sessions: dict[str, float] = {}


@router.get("/home", response_class=HTMLResponse, include_in_schema=False)
def home_page() -> HTMLResponse:
    return HTMLResponse(_layout(title="VortexShield", body=_home_body(), active="home"))


@router.get("/home/api", response_class=HTMLResponse, include_in_schema=False)
def api_console_page() -> HTMLResponse:
    return HTMLResponse(
        _layout(title="VortexShield Access Console", body=_api_console_body(), active="api")
    )


@router.get("/home/admin/login", response_class=HTMLResponse, include_in_schema=False)
def admin_login_page() -> HTMLResponse:
    return HTMLResponse(
        _layout(title="VortexShield Admin Login", body=_admin_login_body(), active="admin")
    )


@router.get(
    "/home/admin",
    response_class=HTMLResponse,
    response_model=None,
    include_in_schema=False,
)
def admin_console_page(request: Request) -> Response:
    if not _is_admin_session_request(request):
        return RedirectResponse(url="/home/admin/login", status_code=status.HTTP_302_FOUND)
    return HTMLResponse(
        _layout(title="VortexShield Admin Console", body=_admin_console_body(), active="admin")
    )


@router.post("/home/admin/api/login", response_model=AdminLoginResponse)
def admin_login(request: AdminLoginRequest, response: Response) -> AdminLoginResponse | JSONResponse:
    if not _is_admin_authorized(request.admin_token):
        return _admin_forbidden()

    session_token = secrets.token_urlsafe(32)
    _admin_sessions[session_token] = time.time() + ADMIN_SESSION_TTL_SECONDS
    response.set_cookie(
        key=ADMIN_COOKIE_NAME,
        value=session_token,
        max_age=ADMIN_SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/home/admin",
    )
    return AdminLoginResponse(data={"redirect": "/home/admin"})


@router.post("/home/admin/api/logout", response_model=AdminLoginResponse)
def admin_logout(request: Request, response: Response) -> AdminLoginResponse:
    token = request.cookies.get(ADMIN_COOKIE_NAME)
    if token:
        _admin_sessions.pop(token, None)
    response.delete_cookie(ADMIN_COOKIE_NAME, path="/home/admin")
    return AdminLoginResponse(data={"redirect": "/home/admin/login"})


@router.get("/home/admin/api/sites", response_model=SiteAdminListResponse)
def admin_list_sites(request: Request) -> SiteAdminListResponse | JSONResponse:
    if not _is_admin_session_request(request):
        return _admin_forbidden()
    return SiteAdminListResponse(data=[_site_to_admin_data(site) for site in site_registry.list_sites()])


@router.post("/home/admin/api/sites/{site_key}/enable", response_model=AdminSiteMutationResponse)
def admin_enable_site(site_key: str, request: Request) -> AdminSiteMutationResponse | JSONResponse:
    if not _is_admin_session_request(request):
        return _admin_forbidden()
    site = site_registry.set_enabled(site_key, True)
    if site is None:
        return _admin_not_found()
    return AdminSiteMutationResponse(data=_site_to_admin_data(site))


@router.post("/home/admin/api/sites/{site_key}/disable", response_model=AdminSiteMutationResponse)
def admin_disable_site(site_key: str, request: Request) -> AdminSiteMutationResponse | JSONResponse:
    if not _is_admin_session_request(request):
        return _admin_forbidden()
    site = site_registry.set_enabled(site_key, False)
    if site is None:
        return _admin_not_found()
    return AdminSiteMutationResponse(data=_site_to_admin_data(site))


@router.post(
    "/home/admin/api/sites/{site_key}/rotate-secret",
    response_model=AdminSecretRotateResponse,
)
def admin_rotate_secret(site_key: str, request: Request) -> AdminSecretRotateResponse | JSONResponse:
    if not _is_admin_session_request(request):
        return _admin_forbidden()
    rotated = site_registry.rotate_secret(site_key)
    if rotated is None:
        return _admin_not_found()
    site, secret = rotated
    return AdminSecretRotateResponse(
        data=AdminSecretRotateData(
            **_site_to_admin_data(site).model_dump(),
            secret=secret,
        )
    )


@router.delete("/home/admin/api/sites/{site_key}", response_model=AdminSiteMutationResponse)
def admin_delete_site(site_key: str, request: Request) -> AdminSiteMutationResponse | JSONResponse:
    if not _is_admin_session_request(request):
        return _admin_forbidden()
    try:
        site = site_registry.delete_site(site_key)
    except ValueError as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": 400, "msg": str(exc), "data": None},
        )
    if site is None:
        return _admin_not_found()
    return AdminSiteMutationResponse(data=_site_to_admin_data(site))


@router.get("/home/admin/api/stats", response_model=AdminStatsResponse)
def admin_stats(request: Request) -> AdminStatsResponse | JSONResponse:
    if not _is_admin_session_request(request):
        return _admin_forbidden()
    sites = site_registry.list_sites()
    enabled_count = sum(1 for site in sites if site.enabled)
    return AdminStatsResponse(
        data=AdminStatsData(
            site_count=len(sites),
            enabled_site_count=enabled_count,
            disabled_site_count=len(sites) - enabled_count,
            storage_path=settings.site_registry_path,
            session_backend="memory-single-worker",
            admin_cookie_name=ADMIN_COOKIE_NAME,
        )
    )


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


def _is_admin_session_request(request: Request) -> bool:
    token = request.cookies.get(ADMIN_COOKIE_NAME)
    if not token:
        return False
    expires_at = _admin_sessions.get(token)
    now = time.time()
    if expires_at is None or expires_at <= now:
        _admin_sessions.pop(token, None)
        return False
    return True


def _admin_forbidden() -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"code": 403, "msg": "admin_token_required", "data": None},
    )


def _admin_not_found() -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"code": 404, "msg": "site_not_found", "data": None},
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
    nav_admin = "is-active" if active == "admin" else ""
    admin_nav = f'<a class="{nav_admin}" href="/home/admin">Ops Console</a>' if active == "admin" else ""
    return f"""<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{escape(title)}</title>
    <style>
      :root {{
        color-scheme: dark;
        --bg: #07100d;
        --bg-2: #0d1714;
        --ink: #e8fff5;
        --muted: #8aa49a;
        --line: rgba(115, 255, 199, 0.16);
        --panel: rgba(10, 25, 20, 0.82);
        --panel-2: rgba(12, 32, 27, 0.64);
        --cyan: #47f2d0;
        --green: #63e88f;
        --amber: #f2c15c;
        --red: #ff6861;
        --blue: #70a5ff;
        --shadow: 0 24px 70px rgba(0, 0, 0, 0.36);
      }}
      * {{ box-sizing: border-box; }}
      html {{ background: var(--bg); }}
      body {{
        margin: 0;
        min-height: 100vh;
        color: var(--ink);
        font-family: "Cascadia Code", "Segoe UI Variable", "Microsoft YaHei", "PingFang SC", sans-serif;
        background:
          radial-gradient(circle at 18% 10%, rgba(71, 242, 208, 0.18), transparent 34%),
          radial-gradient(circle at 82% 24%, rgba(112, 165, 255, 0.14), transparent 30%),
          radial-gradient(circle at 50% 90%, rgba(99, 232, 143, 0.11), transparent 34%),
          linear-gradient(180deg, #07100d 0%, #0b1512 52%, #08100d 100%);
      }}
      body::before {{
        content: "";
        position: fixed;
        inset: 0;
        pointer-events: none;
        background:
          linear-gradient(90deg, rgba(115, 255, 199, 0.055) 1px, transparent 1px),
          linear-gradient(rgba(115, 255, 199, 0.045) 1px, transparent 1px);
        background-size: 36px 36px;
        mask-image: radial-gradient(circle at 50% 20%, black, transparent 76%);
      }}
      body::after {{
        content: "";
        position: fixed;
        inset: 0;
        pointer-events: none;
        background: repeating-linear-gradient(
          180deg,
          rgba(255,255,255,0.025) 0,
          rgba(255,255,255,0.025) 1px,
          transparent 1px,
          transparent 7px
        );
        opacity: 0.28;
      }}
      .shell {{
        width: min(1180px, calc(100% - 32px));
        margin: 0 auto;
        position: relative;
        z-index: 1;
      }}
      header {{
        min-height: 74px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 18px;
        border-bottom: 1px solid rgba(115, 255, 199, 0.1);
      }}
      .brand {{
        display: flex;
        align-items: center;
        gap: 12px;
        color: inherit;
        text-decoration: none;
        font-weight: 900;
        letter-spacing: 0.01em;
      }}
      .brand-mark {{
        width: 40px;
        height: 40px;
        display: grid;
        place-items: center;
        border: 1px solid rgba(71, 242, 208, 0.34);
        border-radius: 8px;
        color: var(--cyan);
        background:
          linear-gradient(135deg, rgba(71, 242, 208, 0.14), rgba(112, 165, 255, 0.12)),
          rgba(3, 10, 8, 0.62);
        box-shadow: 0 0 28px rgba(71, 242, 208, 0.16);
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
        color: #a9c3ba;
        text-decoration: none;
        border: 1px solid transparent;
        font-size: 13px;
        font-weight: 800;
      }}
      nav a.is-active,
      nav a:hover {{
        border-color: rgba(71, 242, 208, 0.24);
        background: rgba(71, 242, 208, 0.08);
        color: var(--ink);
      }}
      main {{ padding: 34px 0 58px; }}
      h1 {{
        margin: 0;
        max-width: 860px;
        font-size: clamp(40px, 6.2vw, 78px);
        line-height: 0.98;
        letter-spacing: 0;
      }}
      .eyebrow {{
        margin: 0 0 14px;
        color: var(--cyan);
        font-size: 12px;
        font-weight: 900;
        letter-spacing: 0.18em;
        text-transform: uppercase;
      }}
      .lead {{
        max-width: 730px;
        margin: 22px 0 0;
        color: var(--muted);
        font-size: 16px;
        line-height: 1.82;
      }}
      .hero,
      .console,
      .admin-login,
      .admin-hero {{
        display: grid;
        grid-template-columns: minmax(0, 1fr) 420px;
        gap: 22px;
        align-items: center;
      }}
      .hero,
      .admin-login {{ min-height: calc(100vh - 176px); }}
      .console,
      .admin-shell {{ align-items: start; }}
      .admin-shell {{ display: grid; gap: 16px; }}
      .panel,
      .card,
      .command-panel,
      .admin-toolbar,
      .admin-assets {{
        border: 1px solid var(--line);
        border-radius: 8px;
        background:
          linear-gradient(180deg, rgba(16, 39, 32, 0.88), rgba(8, 20, 16, 0.88)),
          var(--panel);
        box-shadow: var(--shadow);
        backdrop-filter: blur(18px);
      }}
      .panel,
      .command-panel,
      .admin-toolbar,
      .admin-assets {{ padding: 18px; }}
      .actions,
      .admin-actions {{
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin-top: 26px;
      }}
      .button {{
        min-height: 42px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        padding: 0 16px;
        border-radius: 8px;
        border: 1px solid rgba(115, 255, 199, 0.2);
        background: rgba(10, 28, 23, 0.74);
        color: var(--ink);
        text-decoration: none;
        font: inherit;
        font-size: 13px;
        font-weight: 850;
        cursor: pointer;
      }}
      .button.primary {{
        border-color: rgba(71, 242, 208, 0.44);
        color: #06100d;
        background: linear-gradient(135deg, var(--cyan), var(--green));
        box-shadow: 0 0 26px rgba(71, 242, 208, 0.2);
      }}
      .button.ghost {{ background: rgba(255, 255, 255, 0.04); }}
      .button.danger {{
        color: #fff;
        border-color: rgba(255, 104, 97, 0.36);
        background: linear-gradient(135deg, rgba(255,104,97,0.88), rgba(180,48,45,0.88));
      }}
      .button.small {{
        min-height: 32px;
        padding: 0 10px;
        font-size: 12px;
      }}
      .grid,
      .admin-metrics {{
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 12px;
        margin-top: 24px;
      }}
      .card,
      .admin-metric {{
        padding: 16px;
        background: rgba(9, 24, 19, 0.74);
      }}
      .card h3,
      .admin-metric span {{
        margin: 0 0 8px;
        color: var(--cyan);
        font-size: 13px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }}
      .card p {{
        margin: 0;
        color: var(--muted);
        line-height: 1.6;
        font-size: 13px;
      }}
      .admin-metric b {{
        display: block;
        font-size: 30px;
        line-height: 1;
        color: var(--ink);
      }}
      .command-top,
      .admin-toolbar {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
      }}
      .flow-step {{
        padding: 14px;
        border: 1px solid rgba(115, 255, 199, 0.14);
        border-radius: 8px;
        background: rgba(5, 14, 11, 0.52);
      }}
      .flow-step strong {{
        display: flex;
        justify-content: space-between;
        gap: 8px;
        margin-bottom: 7px;
        color: var(--ink);
      }}
      .flow-step span,
      .muted {{ color: var(--muted); }}
      .status-pill,
      .status-tag {{
        min-height: 26px;
        display: inline-flex;
        align-items: center;
        gap: 7px;
        padding: 0 10px;
        border: 1px solid rgba(99, 232, 143, 0.24);
        border-radius: 999px;
        color: var(--green);
        background: rgba(99, 232, 143, 0.1);
        font-size: 12px;
        font-weight: 900;
      }}
      .status-tag.off {{
        color: var(--red);
        border-color: rgba(255, 104, 97, 0.28);
        background: rgba(255, 104, 97, 0.08);
      }}
      .status-dot {{
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: var(--green);
        box-shadow: 0 0 0 4px rgba(99, 232, 143, 0.12);
      }}
      .console {{
        grid-template-columns: 390px minmax(0, 1fr);
      }}
      .console h1 {{
        margin-bottom: 12px;
        font-size: clamp(28px, 4vw, 52px);
      }}
      label {{
        display: grid;
        gap: 7px;
        margin-top: 14px;
        color: #bde8d9;
        font-size: 12px;
        font-weight: 850;
      }}
      input,
      textarea {{
        width: 100%;
        border: 1px solid rgba(115, 255, 199, 0.18);
        border-radius: 8px;
        padding: 11px 12px;
        background: rgba(1, 8, 6, 0.7);
        color: var(--ink);
        font: inherit;
        outline: none;
      }}
      textarea {{ min-height: 86px; resize: vertical; }}
      input:focus,
      textarea:focus {{
        border-color: rgba(71, 242, 208, 0.56);
        box-shadow: 0 0 0 3px rgba(71, 242, 208, 0.12);
      }}
      .notice {{
        min-height: 22px;
        margin: 12px 0 0;
        color: var(--muted);
        font-size: 13px;
        line-height: 1.5;
      }}
      .notice.ok {{ color: var(--green); }}
      .notice.error,
      .danger {{ color: var(--red); }}
      .table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 12px;
      }}
      .table-wrap {{ width: 100%; overflow-x: auto; }}
      .table th,
      .table td {{
        padding: 12px 10px;
        border-bottom: 1px solid rgba(115, 255, 199, 0.11);
        text-align: left;
        vertical-align: top;
      }}
      .table th {{
        color: #a8cfc2;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
      }}
      code {{
        padding: 2px 6px;
        border-radius: 6px;
        background: rgba(71, 242, 208, 0.1);
        color: var(--cyan);
        overflow-wrap: anywhere;
      }}
      .section-title {{
        margin: 0 0 10px;
        font-size: 12px;
        color: var(--cyan);
        font-weight: 900;
        letter-spacing: 0.16em;
        text-transform: uppercase;
      }}
      .secret-box,
      .admin-secret {{
        display: none;
        margin-top: 14px;
        padding: 14px;
        border-radius: 8px;
        border: 1px solid rgba(242, 193, 92, 0.28);
        background: rgba(242, 193, 92, 0.08);
      }}
      .secret-box.is-visible,
      .admin-secret.is-visible {{ display: block; }}
      .terminal {{
        min-height: 270px;
        display: grid;
        align-content: start;
        gap: 12px;
        overflow: hidden;
      }}
      .terminal-row {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        padding: 10px 0;
        border-bottom: 1px solid rgba(115,255,199,0.1);
        color: var(--muted);
        font-size: 12px;
      }}
      .terminal-row strong {{ color: var(--ink); }}
      @media (max-width: 860px) {{
        header {{ align-items: flex-start; flex-direction: column; padding-top: 18px; }}
        .hero,
        .console,
        .admin-login,
        .admin-hero {{ grid-template-columns: 1fr; }}
        .grid,
        .admin-metrics {{ grid-template-columns: 1fr; }}
        h1 {{ font-size: clamp(34px, 12vw, 52px); }}
        .lead {{ font-size: 15px; }}
        .admin-toolbar,
        .command-top {{ align-items: flex-start; flex-direction: column; }}
      }}
    </style>
  </head>
  <body>
    <div class="shell">
      <header>
        <a class="brand" href="/home"><span class="brand-mark">VS</span><span>VortexShield</span></a>
        <nav>
          <a class="{nav_home}" href="/home">Home</a>
          <a class="{nav_api}" href="/home/api">Access Console</a>
          {admin_nav}
          <a href="/docs">API Docs</a>
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
    <p class="eyebrow">VORTEXSHIELD / BEHAVIORAL TRUST FABRIC</p>
    <h1>把人机验证接入风控中枢</h1>
    <p class="lead">
      VortexShield 以无感预检、轨迹动力学、混合加密与滑块拼合校验组成一条实时防御链。
      它不是营销组件，而是一套可嵌入登录、注册、支付和内容入口的安全执行层。
    </p>
    <div class="actions">
      <a class="button primary" href="/home/api">创建接入凭证</a>
      <a class="button ghost" href="/docs">查看 API</a>
    </div>
    <div class="grid">
      <article class="card"><h3>Signal Mesh</h3><p>环境探针、动作轨迹、站点策略在预检阶段合流，低风险用户无感通过。</p></article>
      <article class="card"><h3>Crypto Link</h3><p>RSA-OAEP 封装 AES-GCM 会话密钥，Payload 全程认证加密。</p></article>
      <article class="card"><h3>Site Verify</h3><p>业务后端必须使用 secret 一次性消费安全签名，前端接入无法绕过服务端验签。</p></article>
    </div>
  </div>
  <aside class="command-panel terminal">
    <div class="command-top">
      <strong>Decision Pipeline</strong>
      <span class="status-pill"><i class="status-dot"></i>ONLINE</span>
    </div>
    <div class="flow-step"><strong>01 SILENT <em>LOW RISK</em></strong><span>干净环境直接签发短时安全凭证。</span></div>
    <div class="flow-step"><strong>02 CHECKBOX <em>MEDIUM</em></strong><span>弱信号访问进入轻交互确认，并继续采集轨迹。</span></div>
    <div class="flow-step"><strong>03 SLIDER <em>HIGH RISK</em></strong><span>滑块拼合精度与轨迹动力学共同判定。</span></div>
    <div class="flow-step"><strong>04 SITEVERIFY <em>SERVER</em></strong><span>业务后端使用私有 secret 完成最终验签。</span></div>
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
        控制台令牌
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
      <p class="notice" id="notice">输入控制台令牌后即可签发站点凭证。</p>
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
      tableBody.innerHTML = `<tr><td colspan="4" class="muted">输入控制台令牌后可查看已配置站点。</td></tr>`;
      return;
    }
    tableBody.innerHTML = (body.data || []).map((site) => `
      <tr>
        <td><code>${escapeHTML(site.site_key)}</code></td>
        <td>${escapeHTML(site.allowed_domains.join(", "))}</td>
        <td>${escapeHTML(site.allowed_actions.join(", "))}</td>
        <td><span class="status-tag ${site.enabled ? "" : "off"}">${site.enabled ? "ONLINE" : "DISABLED"}</span></td>
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


def _admin_login_body() -> str:
    return """
<section class="admin-login">
  <div>
    <p class="eyebrow">VORTEXSHIELD / RESTRICTED OPS</p>
    <h1>项目管理员控制入口</h1>
    <p class="lead">
      该面板只供 VortexShield 项目管理员访问，用于管理站点凭证、状态开关、secret 轮换和运行态信息。
      普通接入方无需访问此页面。
    </p>
  </div>
  <div class="panel">
    <p class="section-title">Operator Login</p>
    <h1 style="font-size:32px;margin-bottom:12px">身份校验</h1>
    <form id="admin-login-form">
      <label>
        管理员令牌
        <input id="admin-token" type="password" placeholder="VSEC_ADMIN_TOKEN" autocomplete="off" />
      </label>
      <button class="button primary" type="submit">进入控制台</button>
      <p class="notice" id="admin-login-notice">登录成功后将写入 HttpOnly 管理员会话 Cookie。</p>
    </form>
  </div>
</section>
<script>
  const loginForm = document.querySelector("#admin-login-form");
  const tokenInput = document.querySelector("#admin-token");
  const notice = document.querySelector("#admin-login-notice");

  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    notice.className = "notice";
    notice.textContent = "正在校验管理员令牌...";
    try {
      const response = await fetch("/home/admin/api/login", {
        method: "POST",
        headers: {"Content-Type": "application/json", "Accept": "application/json"},
        body: JSON.stringify({admin_token: tokenInput.value.trim()}),
      });
      const body = await response.json();
      if (!response.ok || body.code !== 200) {
        throw new Error(body.msg || `HTTP ${response.status}`);
      }
      window.location.href = body.data.redirect || "/home/admin";
    } catch (error) {
      notice.className = "notice error";
      notice.textContent = error instanceof Error ? error.message : String(error);
    }
  });
</script>
"""


def _admin_console_body() -> str:
    return """
<section class="admin-shell">
  <div class="admin-hero">
    <div class="panel">
      <p class="section-title">Ops Console</p>
      <h1>VortexShield 控制面板</h1>
      <p class="lead">管理站点 API、启停接入、轮换 secret，并查看当前单机运行态边界。</p>
      <div class="admin-metrics">
        <div class="admin-metric"><span>Total Sites</span><b id="metric-total">-</b></div>
        <div class="admin-metric"><span>Enabled</span><b id="metric-enabled">-</b></div>
        <div class="admin-metric"><span>Disabled</span><b id="metric-disabled">-</b></div>
      </div>
    </div>
    <div class="panel terminal">
      <div class="command-top">
        <strong>Runtime</strong>
        <span class="status-pill"><i class="status-dot"></i>GUARDED</span>
      </div>
      <div class="terminal-row"><span>Session Backend</span><strong id="runtime-session">-</strong></div>
      <div class="terminal-row"><span>Registry Path</span><strong id="runtime-storage">-</strong></div>
      <div class="terminal-row"><span>Admin Cookie</span><strong id="runtime-cookie">-</strong></div>
    </div>
  </div>

  <div class="admin-toolbar panel">
    <div>
      <p class="section-title">Token Registry</p>
      <strong>站点令牌资产</strong>
      <p class="notice">启停会立即影响 SDK precheck 与 verify；secret 轮换后旧 secret 失效。</p>
    </div>
    <div class="admin-actions">
      <button class="button ghost" id="refresh-btn" type="button">刷新</button>
      <button class="button danger" id="logout-btn" type="button">退出</button>
    </div>
  </div>

  <div class="admin-assets panel">
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr><th>siteKey</th><th>域名</th><th>动作</th><th>状态</th><th>创建时间</th><th>操作</th></tr>
        </thead>
        <tbody id="admin-sites-body"></tbody>
      </table>
    </div>
    <div class="admin-secret" id="admin-secret-box"></div>
    <p class="notice" id="admin-notice">正在加载站点资产...</p>
  </div>
</section>
<script>
  const sitesBody = document.querySelector("#admin-sites-body");
  const notice = document.querySelector("#admin-notice");
  const secretBox = document.querySelector("#admin-secret-box");
  const refreshBtn = document.querySelector("#refresh-btn");
  const logoutBtn = document.querySelector("#logout-btn");

  refreshBtn.addEventListener("click", () => loadAdminData());
  logoutBtn.addEventListener("click", async () => {
    await fetch("/home/admin/api/logout", {method: "POST", headers: {"Accept": "application/json"}});
    window.location.href = "/home/admin/login";
  });

  sitesBody.addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const action = button.dataset.action;
    const siteKey = button.dataset.siteKey;
    if (!action || !siteKey) return;
    if (action === "delete" && !window.confirm("确认删除该站点 API？该操作不可恢复。")) return;
    await mutateSite(siteKey, action);
  });

  loadAdminData();

  async function loadAdminData() {
    secretBox.classList.remove("is-visible");
    notice.className = "notice";
    notice.textContent = "正在同步控制面板...";
    try {
      const [stats, sites] = await Promise.all([
        fetchJSON("/home/admin/api/stats"),
        fetchJSON("/home/admin/api/sites"),
      ]);
      document.querySelector("#metric-total").textContent = stats.data.site_count;
      document.querySelector("#metric-enabled").textContent = stats.data.enabled_site_count;
      document.querySelector("#metric-disabled").textContent = stats.data.disabled_site_count;
      document.querySelector("#runtime-session").textContent = stats.data.session_backend;
      document.querySelector("#runtime-storage").textContent = stats.data.storage_path;
      document.querySelector("#runtime-cookie").textContent = stats.data.admin_cookie_name;
      renderSites(sites.data || []);
      notice.className = "notice ok";
      notice.textContent = "控制面板已同步。";
    } catch (error) {
      handleAdminError(error);
    }
  }

  async function mutateSite(siteKey, action) {
    secretBox.classList.remove("is-visible");
    notice.className = "notice";
    notice.textContent = `正在执行 ${action}...`;
    const method = action === "delete" ? "DELETE" : "POST";
    const suffix = action === "delete" ? "" : `/${action === "rotate" ? "rotate-secret" : action}`;
    try {
      const body = await fetchJSON(`/home/admin/api/sites/${encodeURIComponent(siteKey)}${suffix}`, {method});
      if (action === "rotate") {
        secretBox.innerHTML = `
          <strong>新 secret 只展示一次</strong>
          <p class="muted">请立刻复制到业务后端配置，旧 secret 已失效。</p>
          <p><code>${escapeHTML(body.data.secret)}</code></p>
        `;
        secretBox.classList.add("is-visible");
      }
      await loadAdminData();
    } catch (error) {
      handleAdminError(error);
    }
  }

  function renderSites(sites) {
    if (!sites.length) {
      sitesBody.innerHTML = `<tr><td colspan="6" class="muted">暂无站点 API。</td></tr>`;
      return;
    }
    sitesBody.innerHTML = sites.map((site) => `
      <tr>
        <td><code>${escapeHTML(site.site_key)}</code></td>
        <td>${escapeHTML(site.allowed_domains.join(", "))}</td>
        <td>${escapeHTML(site.allowed_actions.join(", "))}</td>
        <td><span class="status-tag ${site.enabled ? "" : "off"}">${site.enabled ? "ONLINE" : "DISABLED"}</span></td>
        <td>${escapeHTML(site.created_at)}</td>
        <td>
          <div class="admin-actions">
            <button class="button small ghost" data-action="${site.enabled ? "disable" : "enable"}" data-site-key="${escapeAttribute(site.site_key)}">${site.enabled ? "停用" : "启用"}</button>
            <button class="button small ghost" data-action="rotate" data-site-key="${escapeAttribute(site.site_key)}">轮换 secret</button>
            <button class="button small danger" data-action="delete" data-site-key="${escapeAttribute(site.site_key)}">删除</button>
          </div>
        </td>
      </tr>
    `).join("");
  }

  async function fetchJSON(url, options = {}) {
    const response = await fetch(url, {headers: {"Accept": "application/json"}, ...options});
    const body = await response.json();
    if (!response.ok || (body.code && body.code !== 200)) {
      throw new Error(body.msg || `HTTP ${response.status}`);
    }
    return body;
  }

  function handleAdminError(error) {
    notice.className = "notice error";
    notice.textContent = error instanceof Error ? error.message : String(error);
    if (notice.textContent.includes("admin_token_required")) {
      window.setTimeout(() => { window.location.href = "/home/admin/login"; }, 500);
    }
  }

  function escapeHTML(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function escapeAttribute(value) {
    return escapeHTML(value).replace(/`/g, "&#96;");
  }
</script>
"""
