from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

try:
    from playwright.sync_api import (
        Page,
        TimeoutError as PlaywrightTimeoutError,
        sync_playwright,
    )
except ModuleNotFoundError:
    # 允许脚本在尚未安装 Playwright 时仍能打印友好的安装指引，而不是直接抛出导入异常。
    Page = Any  # type: ignore[assignment]
    PlaywrightTimeoutError = TimeoutError  # type: ignore[assignment]
    sync_playwright = None  # type: ignore[assignment]


DEFAULT_URL = "http://127.0.0.1:48923/demo/login.html"
LOG_PATH = Path("logs") / "trajectory_data.jsonl"
PROTECTION_REASONS = {
    "automation_probe_detected": "环境探针命中 navigator.webdriver / 自动化特征",
    "static_uniform_motion_detected": "探测到绝对匀速直线运动",
    "teleportation_detected": "探测到瞬时坐标跃迁/机器代滑",
    "slider_overlap_ratio_too_low": "滑块面积重合率未达到动态容错阈值",
    "high_risk_slider_trajectory": "滑块轨迹风险分过高，即使命中缺口也拒绝",
    "slider_position_mismatch": "滑块拼接坐标未命中真实缺口",
    "payload_decrypt_failed": "加密包认证失败或被篡改",
}


def main() -> int:
    ensure_utf8_stdio()

    parser = argparse.ArgumentParser(
        description="VortexShield 红蓝对抗自动化攻击脚本",
    )
    parser.add_argument(
        "--mode",
        choices=("uniform_drag", "js_teleport"),
        default="uniform_drag",
        help="攻击模式：匀速拖动或 JS 瞬移篡改。",
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        help=f"登录页地址，默认 {DEFAULT_URL}",
    )
    parser.add_argument(
        "--distance",
        type=int,
        default=180,
        help="攻击拖动/瞬移的水平距离，故意不读取真实 target_x。",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="使用无头浏览器运行。默认展示浏览器，便于观察 UI 抖动。",
    )
    parser.add_argument(
        "--slow-mo",
        type=int,
        default=0,
        help="Playwright slow_mo 毫秒数，调试可设为 40。",
    )
    args = parser.parse_args()

    before_log_size = LOG_PATH.stat().st_size if LOG_PATH.exists() else 0
    console_messages: list[str] = []

    print_banner("VortexShield Red Team Simulation")
    print(f"[*] 目标页面: {args.url}")
    print(f"[*] 攻击模式: {args.mode}")
    print("[*] 预期结果: 验证失败，UI 出现失败反馈，logs/trajectory_data.jsonl 产生 is_passed=false 样本")

    if sync_playwright is None:
        print("\n[!] 当前虚拟环境未安装 Playwright，无法启动浏览器自动化。")
        print("[*] 安装命令：")
        print(r"    .\.venv\Scripts\python.exe -m pip install playwright")
        print(r"    .\.venv\Scripts\python.exe -m playwright install chromium")
        return 3

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=args.headless, slow_mo=args.slow_mo)
        context = browser.new_context(viewport={"width": 1366, "height": 860})
        page = context.new_page()
        page.on("console", lambda msg: console_messages.append(f"{msg.type}: {msg.text}"))

        try:
            open_login_page(page, args.url)
            force_slider_challenge(page)

            if args.mode == "uniform_drag":
                uniform_drag(page, args.distance)
            else:
                js_teleport(page, args.distance)

            feedback = collect_feedback(page, before_log_size, console_messages)
            print_result(feedback)
            return 0 if feedback["blocked"] else 2
        finally:
            context.close()
            browser.close()


def open_login_page(page: Page, url: str) -> None:
    """打开业务登录页并填写账号密码。

    Playwright 默认会暴露 navigator.webdriver=true。这个自动化特征正对应
    risk_engine.py 中 evaluate_environment/_detect_automation_probe 的硬拦截规则：
    webdriver / fake_webdriver / automation_globals 命中即 HIGH 风险。
    """

    page.goto(url, wait_until="domcontentloaded", timeout=15_000)
    page.fill("#account", "attacker@botnet.local")
    page.fill("#password", "P@ssw0rd-from-script")
    print("[*] 已打开登录页并填入自动化测试账号。")


def force_slider_challenge(page: Page) -> None:
    """等待或强制刷新到 SLIDER 滑块校验流程。

    由于 Playwright 环境通常会命中 webdriver 探针，正常会直接降级为 SLIDER。
    如果页面短暂处于 SILENT/CHECKBOX 状态，则等待 SDK 完成刷新。
    """

    try:
        page.wait_for_selector(".vsec-knob", timeout=12_000)
        print("[*] 已进入滑块校验流程。")
    except PlaywrightTimeoutError as exc:
        notice = safe_text(page, "#notice")
        raise RuntimeError(f"未能进入滑块校验流程，当前提示: {notice}") from exc


def uniform_drag(page: Page, distance: int) -> None:
    """使用绝对匀速直线拖动攻击滑块。

    攻击含义：
    - 每一步横向位移相同；
    - 每一步时间间隔近似相同；
    - Y 轴固定为同一条水平线。

    对应 risk_engine.py 的硬拦截规则：
    - extract_trajectory_features 会计算相邻点速度 v；
    - 若存在移动且 velocity_std 极小，则命中 static_uniform_motion_detected；
    - 如果距离设置过大或步数过少，也可能命中 teleportation_detected。
    """

    knob = page.locator(".vsec-knob").first
    box = knob.bounding_box()
    if not box:
        raise RuntimeError("无法定位滑块按钮 .vsec-knob")

    start_x = box["x"] + box["width"] / 2
    start_y = box["y"] + box["height"] / 2
    steps = 24
    step_x = distance / steps
    interval_seconds = 0.018

    print(f"[*] 发起匀速拖动攻击: distance={distance}px, steps={steps}, fixed_dt={interval_seconds}s")
    page.mouse.move(start_x, start_y)
    page.mouse.down()
    for index in range(1, steps + 1):
        page.mouse.move(start_x + step_x * index, start_y)
        time.sleep(interval_seconds)
    page.mouse.up()


def js_teleport(page: Page, distance: int) -> None:
    """直接用 JS 修改滑块和拼图块位置，模拟瞬移篡改。

    攻击含义：
    - 不经过真实拖动过程；
    - 直接修改 DOM transform，把 knob/piece 瞬间移动到某个 X；
    - 再派发极少量鼠标事件，试图让前端提交。

    对应 risk_engine.py 的硬拦截规则：
    - 如果前端成功提交，轨迹点之间会出现极大的瞬时速度，命中 teleportation_detected；
    - 如果提交失败或坐标不准，则命中 slider_overlap_ratio_too_low；
    - 自动化环境也会先被 automation_probe_detected 拦截。
    """

    print(f"[*] 发起 JS 瞬移攻击: transform translateX({distance}px)")
    result = page.evaluate(
        """
        async (distance) => {
          const knob = document.querySelector(".vsec-knob");
          const piece = document.querySelector(".vsec-piece");
          const track = document.querySelector(".vsec-track");
          if (!knob || !piece || !track) {
            return { ok: false, reason: "slider_nodes_missing" };
          }

          knob.style.transform = `translate3d(${distance}px, 0, 0)`;
          piece.style.transform = `translate3d(${distance}px, 0, 0)`;

          const rect = knob.getBoundingClientRect();
          const y = rect.top + rect.height / 2;
          const x0 = rect.left + rect.width / 2;
          const x1 = x0 + distance;

          knob.dispatchEvent(new MouseEvent("mousedown", {
            bubbles: true,
            cancelable: true,
            clientX: x0,
            clientY: y,
          }));
          window.dispatchEvent(new MouseEvent("mousemove", {
            bubbles: true,
            cancelable: true,
            clientX: x1,
            clientY: y,
          }));
          window.dispatchEvent(new MouseEvent("mouseup", {
            bubbles: true,
            cancelable: true,
            clientX: x1,
            clientY: y,
          }));
          return { ok: true };
        }
        """,
        distance,
    )
    if not result.get("ok"):
        raise RuntimeError(f"JS 瞬移攻击初始化失败: {result}")


def collect_feedback(
    page: Page,
    before_log_size: int,
    console_messages: list[str],
) -> dict[str, Any]:
    """采集页面反馈、浏览器 console 和 JSONL 最新日志。"""

    page.wait_for_timeout(1800)
    card_is_error = page.locator(".vsec-card.is-error").count() > 0
    notice = safe_text(page, "#notice")
    latest_log = read_latest_new_log(before_log_size)
    reason = str(latest_log.get("reason") or "")
    is_passed = latest_log.get("is_passed")

    blocked_by_log = is_passed is False and reason in PROTECTION_REASONS
    blocked_by_ui = card_is_error or "失败" in notice or "failed" in notice.lower()

    return {
        "blocked": bool(blocked_by_log or blocked_by_ui),
        "card_is_error": card_is_error,
        "notice": notice,
        "latest_log": latest_log,
        "console_tail": console_messages[-8:],
        "reason": reason,
    }


def read_latest_new_log(before_log_size: int) -> dict[str, Any]:
    if not LOG_PATH.exists():
        return {}

    with LOG_PATH.open("rb") as file:
        file.seek(before_log_size)
        chunk = file.read().decode("utf-8", errors="replace")

    lines = [line for line in chunk.splitlines() if line.strip()]
    if not lines:
        return {}

    try:
        return json.loads(lines[-1])
    except json.JSONDecodeError:
        return {"raw": lines[-1]}


def print_result(feedback: dict[str, Any]) -> None:
    latest_log = feedback["latest_log"]
    reason = feedback["reason"]
    description = PROTECTION_REASONS.get(reason, reason or "UI failure feedback")

    print("\n" + "=" * 78)
    if feedback["blocked"]:
        print(f"[+] 成功触发防护机制：{description}，验证被拒绝！")
    else:
        print("[!] 未观察到明确拦截信号，请检查服务是否启动、日志是否写入或攻击距离是否过小。")

    print("-" * 78)
    print(f"UI error class : {feedback['card_is_error']}")
    print(f"页面提示       : {feedback['notice']}")
    print(f"日志 reason    : {reason or '(none)'}")
    print(f"日志 is_passed : {latest_log.get('is_passed') if latest_log else '(none)'}")
    print(f"日志 risk_score: {latest_log.get('risk_score') if latest_log else '(none)'}")
    if feedback["console_tail"]:
        print("-" * 78)
        print("浏览器 Console 末尾:")
        for message in feedback["console_tail"]:
            print(f"  {message}")
    print("=" * 78 + "\n")


def safe_text(page: Page, selector: str) -> str:
    try:
        locator = page.locator(selector).first
        if locator.count() == 0:
            return ""
        return locator.inner_text(timeout=800).strip()
    except Exception:
        return ""


def print_banner(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def ensure_utf8_stdio() -> None:
    """尽量让 Windows 终端也能稳定显示中文结论。

    这只影响本脚本的输出编码，不改变业务代码或系统全局配置。
    """

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8")
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
