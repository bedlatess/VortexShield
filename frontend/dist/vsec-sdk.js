"use strict";
const EVENT_MOVE = 0;
const EVENT_DOWN = 1;
const EVENT_UP = 2;
const STYLE_ID = "vsec-sdk-style";
const WIDGET_WIDTH = 320;
const SLIDER_TRACK_HEIGHT = 44;
const SLIDER_KNOB_SIZE = 44;
const I18N = {
    zh: {
        ariaLabel: "VortexShield 安全验证",
        idleTitle: "等待安全验证",
        idleSubtitle: "VortexShield 将自动选择验证方式",
        verifying: "安全验证中...",
        fetchingChallenge: "正在获取挑战...",
        refreshingChallenge: "正在刷新挑战...",
        evaluating: "正在评估浏览器环境与会话完整性",
        passed: "✅ 验证通过",
        passedSubtitle: "行为可信，已完成无感校验",
        verifyHuman: "验证您是真人",
        checkboxPrompt: "请点击复选框完成安全确认",
        sliderPrompt: "拖动滑块，使拼图与缺口完全重合",
        sliderTrack: "按住滑块，拖动完成拼图",
        sliderAria: "拖动滑块完成验证",
        failedTitle: "验证失败，请重试",
        failedSubtitle: "正在刷新挑战",
    },
    en: {
        ariaLabel: "VortexShield security verification",
        idleTitle: "Waiting for verification",
        idleSubtitle: "VortexShield will choose the verification mode",
        verifying: "Verifying...",
        fetchingChallenge: "Loading challenge...",
        refreshingChallenge: "Refreshing challenge...",
        evaluating: "Checking browser environment and session integrity",
        passed: "✅ Verification passed",
        passedSubtitle: "Trusted behavior confirmed",
        verifyHuman: "Verify you are human",
        checkboxPrompt: "Click the checkbox to continue",
        sliderPrompt: "Drag the slider to match the puzzle piece",
        sliderTrack: "Hold and drag to complete the puzzle",
        sliderAria: "Drag the slider to verify",
        failedTitle: "Verification failed, try again",
        failedSubtitle: "Refreshing challenge",
    },
};
class CaptchaSDK {
    constructor(options) {
        this.state = "idle";
        this.challenge = null;
        this.checkboxChallenge = null;
        this.startTime = performance.now();
        this.tracks = [];
        this.cleanupCallbacks = [];
        this.lastMoveSampleAt = 0;
        this.activePointerArea = null;
        this.refreshTimer = null;
        this.sliderStage = null;
        this.sliderPiece = null;
        this.sliderTrack = null;
        this.sliderFill = null;
        this.sliderKnob = null;
        this.sliderX = 0;
        this.sliderDragStartClientX = 0;
        this.sliderDragStartX = 0;
        this.sliderMaxX = 0;
        ensureSDKStyles();
        this.container = this.resolveContainer(options.container);
        this.apiBaseUrl = options.apiBaseUrl.replace(/\/$/, "");
        this.simulateBot = options.simulateBot ?? false;
        this.onSilentPass = options.onSilentPass;
        this.onChallengeRequired = options.onChallengeRequired;
        this.onReady = options.onReady;
        this.onComplete = options.onComplete;
        this.onSuccess = options.onSuccess;
        this.onFailure = options.onFailure;
        this.onError = options.onError;
        this.locale = this.detectLocale();
        this.root = document.createElement("div");
        this.root.className = "vsec-card";
        this.root.setAttribute("role", "group");
        this.root.setAttribute("aria-label", this.t("ariaLabel"));
        this.root.dataset.locale = this.locale;
        this.bodyEl = document.createElement("div");
        this.bodyEl.className = "vsec-body";
        this.footerEl = document.createElement("div");
        this.footerEl.className = "vsec-footer";
        this.footerEl.innerHTML = `<span class="vsec-brand-dot"></span><span>VortexShield</span>`;
        this.root.replaceChildren(this.bodyEl, this.footerEl);
        this.container.replaceChildren(this.root);
        this.renderIdle();
    }
    setSimulateBot(enabled) {
        this.simulateBot = enabled;
    }
    async execute() {
        this.resetRuntimeState();
        this.setState("prechecking");
        this.renderSilentLoading(this.t("verifying"));
        try {
            const fingerprint = await this.collectFingerprint();
            const precheckKey = await this.fetchPrecheckKey();
            const encrypted = await this.encryptHybridPayload({
                client_time: Date.now(),
                fingerprint,
            }, precheckKey.rsa_public_key);
            const response = await fetch(`${this.apiBaseUrl}/api/captcha/precheck`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Accept: "application/json",
                },
                body: JSON.stringify({
                    precheck_token: precheckKey.precheck_token,
                    payload: encrypted,
                }),
            });
            const result = (await response.json());
            if (!response.ok || result.code !== 200) {
                const reason = result?.data?.reason || result?.msg || `precheck_${response.status}`;
                await this.failAndRefresh(reason, result);
                return;
            }
            if (result.data.captcha_type === "SILENT" && result.data.verify_signature) {
                this.setState("silent_passed");
                this.renderSilentSuccess();
                this.onSilentPass?.(result.data.verify_signature, result);
                this.onSuccess?.(result.data.verify_signature, result);
                return;
            }
            if (result.data.captcha_type === "CLICK_CHECKBOX") {
                const challenge = this.normalizeCheckboxChallenge(result.data.challenge);
                this.onChallengeRequired?.(challenge, result);
                await this.activateCheckboxChallenge(challenge);
                return;
            }
            if (result.data.captcha_type === "SLIDER" && isSliderChallenge(result.data.challenge)) {
                this.onChallengeRequired?.(result.data.challenge, result);
                await this.activateSliderChallenge(result.data.challenge);
                return;
            }
            await this.failAndRefresh("unexpected_precheck_action", result);
        }
        catch (error) {
            this.handleFatalError(error);
            throw error;
        }
    }
    async loadChallenge() {
        this.resetRuntimeState();
        this.setState("prechecking");
        this.renderSilentLoading(this.t("fetchingChallenge"));
        const challenge = await this.fetchSliderChallenge();
        await this.activateSliderChallenge(challenge);
    }
    destroy() {
        this.clearRefreshTimer();
        for (const cleanup of this.cleanupCallbacks) {
            cleanup();
        }
        this.cleanupCallbacks = [];
    }
    renderIdle() {
        this.setState("idle");
        this.bodyEl.innerHTML = `
      <div class="vsec-status-row">
        <span class="vsec-orb vsec-orb-idle"></span>
        <div class="vsec-copy">
          <div class="vsec-title">${escapeHTML(this.t("idleTitle"))}</div>
          <div class="vsec-subtitle">${escapeHTML(this.t("idleSubtitle"))}</div>
        </div>
      </div>
    `;
    }
    renderSilentLoading(text) {
        this.bodyEl.innerHTML = `
      <div class="vsec-status-row vsec-status-row-airy">
        <span class="vsec-spinner" aria-hidden="true"></span>
          <div class="vsec-copy">
            <div class="vsec-title">${escapeHTML(text)}</div>
          <div class="vsec-subtitle">${escapeHTML(this.t("evaluating"))}</div>
        </div>
      </div>
      <div class="vsec-progress"><span></span></div>
    `;
    }
    renderSilentSuccess() {
        this.bodyEl.innerHTML = `
      <div class="vsec-status-row vsec-success-sweep">
        <span class="vsec-checkmark" aria-hidden="true">
          <svg viewBox="0 0 24 24" focusable="false">
            <path d="M20 6 9 17l-5-5"></path>
          </svg>
        </span>
        <div class="vsec-copy">
          <div class="vsec-title">${escapeHTML(this.t("passed"))}</div>
          <div class="vsec-subtitle">${escapeHTML(this.t("passedSubtitle"))}</div>
        </div>
      </div>
    `;
    }
    async activateCheckboxChallenge(challenge) {
        this.resetInteractionState();
        this.checkboxChallenge = challenge;
        this.setState("checkbox_ready");
        this.startTime = performance.now();
        const box = document.createElement("button");
        box.type = "button";
        box.className = "vsec-checkbox-widget";
        box.innerHTML = `
      <span class="vsec-checkbox-mark" aria-hidden="true"></span>
      <span class="vsec-checkbox-copy">
        <strong>${escapeHTML(this.t("verifyHuman"))}</strong>
        <small>${escapeHTML(this.localizedPrompt(challenge.prompt, "checkboxPrompt"))}</small>
      </span>
      <span class="vsec-checkbox-pulse" aria-hidden="true"></span>
    `;
        this.bodyEl.replaceChildren(box);
        this.activePointerArea = box;
        const moveHandler = (event) => this.recordSampledEvent(event, EVENT_MOVE, box);
        const clickHandler = async (event) => {
            event.preventDefault();
            this.recordPointerEvent(event, EVENT_DOWN, box);
            this.recordPointerEvent(event, EVENT_UP, box);
            box.classList.add("is-loading");
            this.setState("checkbox_verifying");
            await this.submitCheckboxVerify();
        };
        box.addEventListener("mousemove", moveHandler, { passive: true });
        box.addEventListener("click", clickHandler);
        this.cleanupCallbacks.push(() => box.removeEventListener("mousemove", moveHandler));
        this.cleanupCallbacks.push(() => box.removeEventListener("click", clickHandler));
        this.onReady?.(challenge);
    }
    async activateSliderChallenge(challenge) {
        this.resetInteractionState();
        this.challenge = challenge;
        this.setState("slider_ready");
        this.startTime = performance.now();
        this.sliderX = Number(challenge.initial_x || 0);
        const shell = document.createElement("div");
        shell.className = "vsec-slider-shell";
        shell.innerHTML = `
      <div class="vsec-slider-prompt">${escapeHTML(this.localizedPrompt(challenge.prompt, "sliderPrompt"))}</div>
      <div class="vsec-stage" style="width:${challenge.dimensions.width}px;height:${challenge.dimensions.height}px">
        <img class="vsec-bg" alt="" draggable="false" src="${escapeAttribute(challenge.bg_image)}" />
        <img class="vsec-piece" alt="" draggable="false" src="${escapeAttribute(challenge.slider_piece_b64)}" />
      </div>
      <div class="vsec-track" aria-label="${escapeAttribute(this.t("sliderAria"))}">
        <div class="vsec-track-fill"></div>
        <div class="vsec-track-text">${escapeHTML(this.t("sliderTrack"))}</div>
        <button class="vsec-knob" type="button" aria-label="${escapeAttribute(this.t("sliderAria"))}">
          <span></span>
        </button>
      </div>
    `;
        this.bodyEl.replaceChildren(shell);
        this.sliderStage = shell.querySelector(".vsec-stage");
        this.sliderPiece = shell.querySelector(".vsec-piece");
        this.sliderTrack = shell.querySelector(".vsec-track");
        this.sliderFill = shell.querySelector(".vsec-track-fill");
        this.sliderKnob = shell.querySelector(".vsec-knob");
        if (!this.sliderStage || !this.sliderPiece || !this.sliderTrack || !this.sliderFill || !this.sliderKnob) {
            throw new Error("Slider UI failed to initialize.");
        }
        this.sliderPiece.style.width = `${challenge.piece_size.width}px`;
        this.sliderPiece.style.height = `${challenge.piece_size.height}px`;
        this.sliderPiece.style.top = `${this.clampPieceY(challenge.piece_y, challenge)}px`;
        this.activePointerArea = this.sliderTrack;
        this.computeSliderBounds();
        this.applySliderX(this.sliderX, false);
        this.bindSliderEvents();
        this.onReady?.(challenge);
    }
    bindSliderEvents() {
        const knob = this.sliderKnob;
        if (!knob) {
            return;
        }
        const downHandler = (event) => {
            event.preventDefault();
            const clientX = getClientX(event);
            this.computeSliderBounds();
            this.setState("slider_dragging");
            this.sliderDragStartClientX = clientX;
            this.sliderDragStartX = this.sliderX;
            this.root.classList.add("is-dragging");
            this.recordSyntheticTrack(clientX, getClientY(event), EVENT_DOWN);
            window.addEventListener("mousemove", moveHandler, { passive: false });
            window.addEventListener("mouseup", upHandler);
            window.addEventListener("touchmove", moveHandler, { passive: false });
            window.addEventListener("touchend", upHandler);
            window.addEventListener("touchcancel", upHandler);
        };
        const moveHandler = (event) => {
            event.preventDefault();
            const clientX = getClientX(event);
            const delta = clientX - this.sliderDragStartClientX;
            const nextX = this.clampSliderX(this.sliderDragStartX + delta);
            this.applySliderX(nextX, true);
            this.recordSampledSyntheticTrack(clientX, getClientY(event), EVENT_MOVE);
        };
        const upHandler = async (event) => {
            this.root.classList.remove("is-dragging");
            this.setState("verifying");
            this.recordSyntheticTrack(getClientX(event), getClientY(event), EVENT_UP);
            window.removeEventListener("mousemove", moveHandler);
            window.removeEventListener("mouseup", upHandler);
            window.removeEventListener("touchmove", moveHandler);
            window.removeEventListener("touchend", upHandler);
            window.removeEventListener("touchcancel", upHandler);
            await this.submitSliderVerify();
        };
        knob.addEventListener("mousedown", downHandler);
        knob.addEventListener("touchstart", downHandler, { passive: false });
        this.cleanupCallbacks.push(() => knob.removeEventListener("mousedown", downHandler));
        this.cleanupCallbacks.push(() => knob.removeEventListener("touchstart", downHandler));
        this.cleanupCallbacks.push(() => window.removeEventListener("mousemove", moveHandler));
        this.cleanupCallbacks.push(() => window.removeEventListener("mouseup", upHandler));
        this.cleanupCallbacks.push(() => window.removeEventListener("touchmove", moveHandler));
        this.cleanupCallbacks.push(() => window.removeEventListener("touchend", upHandler));
        this.cleanupCallbacks.push(() => window.removeEventListener("touchcancel", upHandler));
    }
    async submitCheckboxVerify() {
        if (!this.checkboxChallenge?.captcha_token || !this.checkboxChallenge.rsa_public_key) {
            await this.failAndRefresh("checkbox_token_unavailable", {
                code: 409,
                msg: "checkbox challenge is missing token or RSA public key",
            });
            return;
        }
        const plaintext = {
            client_time: Date.now(),
            captcha_token: this.checkboxChallenge.captcha_token,
            captcha_type: "CLICK_CHECKBOX",
            checkbox_checked: true,
            tracks: this.tracks.slice(),
            fingerprint: await this.collectFingerprint(),
        };
        const encrypted = await this.encryptHybridPayload(plaintext, this.checkboxChallenge.rsa_public_key);
        await this.submitVerify({
            captcha_token: this.checkboxChallenge.captcha_token,
            captcha_type: "CLICK_CHECKBOX",
            plaintext,
            encrypted,
        });
    }
    async submitSliderVerify() {
        if (!this.challenge) {
            await this.failAndRefresh("slider_challenge_missing", null);
            return;
        }
        this.setState("verifying");
        this.root.classList.add("is-verifying");
        const plaintext = {
            client_time: Date.now(),
            captcha_token: this.challenge.captcha_token,
            captcha_type: "SLIDER",
            slider_x: Math.round(this.sliderX * 1000) / 1000,
            tracks: this.tracks.slice(),
            fingerprint: await this.collectFingerprint(),
        };
        const encrypted = await this.encryptHybridPayload(plaintext, this.challenge.rsa_public_key);
        await this.submitVerify({
            captcha_token: this.challenge.captcha_token,
            captcha_type: "SLIDER",
            plaintext,
            encrypted,
        });
    }
    async submitVerify(bundle) {
        try {
            this.onComplete?.(bundle);
            const response = await fetch(`${this.apiBaseUrl}/api/captcha/verify`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Accept: "application/json",
                },
                body: JSON.stringify({
                    captcha_token: bundle.captcha_token,
                    payload: bundle.encrypted,
                }),
            });
            const result = await response.json();
            if (response.ok && result.code === 200 && result.data?.verify_signature) {
                this.root.classList.remove("is-verifying");
                this.setState("silent_passed");
                this.renderSilentSuccess();
                this.onSuccess?.(result.data.verify_signature, result);
                return;
            }
            const reason = result?.data?.reason || result?.msg || `verify_${response.status}`;
            await this.failAndRefresh(reason, result);
        }
        catch (error) {
            this.handleFatalError(error);
        }
    }
    async failAndRefresh(reason, response) {
        this.setState("failed");
        this.root.classList.remove("is-verifying", "is-dragging");
        this.root.classList.add("is-error");
        this.renderFailure(reason);
        this.onFailure?.(reason, response);
        this.clearRefreshTimer();
        this.refreshTimer = window.setTimeout(async () => {
            this.root.classList.remove("is-error");
            try {
                this.renderSilentLoading(this.t("refreshingChallenge"));
                const challenge = await this.fetchSliderChallenge();
                await this.activateSliderChallenge(challenge);
            }
            catch (error) {
                this.handleFatalError(error);
            }
        }, 760);
    }
    renderFailure(reason) {
        this.bodyEl.innerHTML = `
      <div class="vsec-status-row">
        <span class="vsec-failmark" aria-hidden="true">!</span>
        <div class="vsec-copy">
          <div class="vsec-title">${escapeHTML(this.t("failedTitle"))}</div>
          <div class="vsec-subtitle">${escapeHTML(`${reason} · ${this.t("failedSubtitle")}`)}</div>
        </div>
      </div>
    `;
    }
    async fetchSliderChallenge() {
        const response = await fetch(`${this.apiBaseUrl}/api/captcha/challenge`, {
            method: "GET",
            headers: { Accept: "application/json" },
        });
        if (!response.ok) {
            throw new Error(`Challenge request failed: ${response.status}`);
        }
        const body = (await response.json());
        if (body.code !== 200 || !isSliderChallenge(body.data)) {
            throw new Error(`Unexpected challenge response: ${body.msg || "unknown"}`);
        }
        return body.data;
    }
    async fetchPrecheckKey() {
        const response = await fetch(`${this.apiBaseUrl}/api/captcha/precheck-key`, {
            method: "GET",
            headers: { Accept: "application/json" },
        });
        if (!response.ok) {
            throw new Error(`Precheck key request failed: ${response.status}`);
        }
        const body = (await response.json());
        if (body.code !== 200 || !body.data?.rsa_public_key || !body.data?.precheck_token) {
            throw new Error(`Unexpected precheck-key response: ${body.msg || "unknown"}`);
        }
        return body.data;
    }
    computeSliderBounds() {
        if (!this.sliderTrack || !this.challenge) {
            this.sliderMaxX = 0;
            return;
        }
        const trackWidth = this.sliderTrack.getBoundingClientRect().width || WIDGET_WIDTH;
        const trackMax = Math.max(0, trackWidth - SLIDER_KNOB_SIZE);
        const pieceMax = Math.max(0, this.challenge.dimensions.width - this.challenge.piece_size.width);
        this.sliderMaxX = Math.min(trackMax, pieceMax);
    }
    applySliderX(nextX, dragging) {
        this.sliderX = this.clampSliderX(nextX);
        const x = `${this.sliderX}px`;
        if (this.sliderPiece) {
            this.sliderPiece.style.transform = `translate3d(${x}, 0, 0)`;
            this.sliderPiece.style.transition = dragging ? "none" : "";
        }
        if (this.sliderKnob) {
            this.sliderKnob.style.transform = `translate3d(${x}, 0, 0)`;
            this.sliderKnob.style.transition = dragging ? "none" : "";
        }
        if (this.sliderFill) {
            this.sliderFill.style.width = `${this.sliderX + SLIDER_KNOB_SIZE / 2}px`;
        }
    }
    clampSliderX(value) {
        if (!Number.isFinite(value)) {
            return 0;
        }
        return Math.max(0, Math.min(this.sliderMaxX, value));
    }
    clampPieceY(value, challenge) {
        const maxY = Math.max(0, challenge.dimensions.height - challenge.piece_size.height);
        if (!Number.isFinite(value)) {
            return Math.round(maxY / 2);
        }
        return Math.max(0, Math.min(maxY, value));
    }
    recordSampledEvent(event, eventType, area) {
        const now = performance.now();
        if (now - this.lastMoveSampleAt < 4) {
            return null;
        }
        this.lastMoveSampleAt = now;
        return this.recordPointerEvent(event, eventType, area);
    }
    recordPointerEvent(event, eventType, area) {
        const point = this.toLocalPoint(event.clientX, event.clientY, area);
        const timestamp = Math.max(1, Math.round(performance.now() - this.startTime));
        const track = [point.x, point.y, timestamp, eventType];
        this.tracks.push(track);
        return track;
    }
    recordSampledSyntheticTrack(clientX, clientY, eventType) {
        const now = performance.now();
        if (now - this.lastMoveSampleAt < 4) {
            return null;
        }
        this.lastMoveSampleAt = now;
        return this.recordSyntheticTrack(clientX, clientY, eventType);
    }
    recordSyntheticTrack(clientX, clientY, eventType) {
        const area = this.activePointerArea || this.root;
        const point = this.toLocalPoint(clientX, clientY, area);
        const timestamp = Math.max(1, Math.round(performance.now() - this.startTime));
        const track = [point.x, point.y, timestamp, eventType];
        this.tracks.push(track);
        return track;
    }
    toLocalPoint(clientX, clientY, area) {
        const rect = area.getBoundingClientRect();
        const x = Math.round(clientX - rect.left);
        const y = Math.round(clientY - rect.top);
        return {
            x: Math.max(0, Math.min(Math.round(rect.width), x)),
            y: Math.max(0, Math.min(Math.round(rect.height), y)),
        };
    }
    resetRuntimeState() {
        this.destroy();
        this.challenge = null;
        this.checkboxChallenge = null;
        this.resetInteractionState();
        this.root.classList.remove("is-error", "is-verifying", "is-dragging");
    }
    resetInteractionState() {
        for (const cleanup of this.cleanupCallbacks) {
            cleanup();
        }
        this.cleanupCallbacks = [];
        this.tracks = [];
        this.lastMoveSampleAt = 0;
        this.activePointerArea = null;
        this.sliderStage = null;
        this.sliderPiece = null;
        this.sliderTrack = null;
        this.sliderFill = null;
        this.sliderKnob = null;
        this.sliderX = 0;
        this.sliderDragStartClientX = 0;
        this.sliderDragStartX = 0;
        this.sliderMaxX = 0;
        this.startTime = performance.now();
    }
    normalizeCheckboxChallenge(challenge) {
        if (isCheckboxChallenge(challenge)) {
            return challenge;
        }
        return {
            captcha_token: "",
            captcha_type: "CLICK_CHECKBOX",
            prompt: this.t("checkboxPrompt"),
            rsa_public_key: "",
        };
    }
    detectLocale() {
        return navigator.language?.toLowerCase().startsWith("zh") ? "zh" : "en";
    }
    t(key) {
        return I18N[this.locale][key];
    }
    localizedPrompt(prompt, fallbackKey) {
        if (this.locale === "en") {
            return this.t(fallbackKey);
        }
        return prompt || this.t(fallbackKey);
    }
    setState(state) {
        this.state = state;
        this.root.dataset.state = state;
    }
    handleFatalError(error) {
        this.setState("failed");
        this.root.classList.add("is-error");
        const message = error instanceof Error ? error.message : String(error);
        this.renderFailure(message);
        this.onError?.(error);
    }
    clearRefreshTimer() {
        if (this.refreshTimer !== null) {
            window.clearTimeout(this.refreshTimer);
            this.refreshTimer = null;
        }
    }
    async encryptHybridPayload(payload, rsaPublicKeyPem) {
        const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
        const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ivBuffer = iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength);
        const encoded = new TextEncoder().encode(JSON.stringify(payload));
        const encryptedPayload = await crypto.subtle.encrypt({ name: "AES-GCM", iv: ivBuffer }, aesKey, encoded);
        const rsaPublicKey = await this.importRsaPublicKey(rsaPublicKeyPem);
        const encryptedKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsaPublicKey, rawAesKey);
        return {
            version: "vsec-rsa-oaep-aes-gcm@phase5",
            alg: "RSA-OAEP-2048-SHA256+A256GCM",
            encrypted_key: this.arrayBufferToBase64(encryptedKey),
            encrypted_payload: {
                iv: this.arrayBufferToBase64(iv),
                ciphertext: this.arrayBufferToBase64(encryptedPayload),
            },
        };
    }
    async importRsaPublicKey(pem) {
        const b64 = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace(/\s/g, "");
        const der = this.base64ToUint8Array(b64);
        const keyBuffer = der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength);
        return crypto.subtle.importKey("spki", keyBuffer, {
            name: "RSA-OAEP",
            hash: "SHA-256",
        }, false, ["encrypt"]);
    }
    async collectFingerprint() {
        const automationGlobals = [
            "__webdriver_evaluate",
            "__selenium_evaluate",
            "__webdriver_script_function",
            "__webdriver_script_func",
            "__webdriver_script_fn",
            "__fxdriver_evaluate",
            "__driver_unwrapped",
            "__webdriver_unwrapped",
            "__driver_evaluate",
            "__selenium_unwrapped",
            "__fxdriver_unwrapped",
            "domAutomation",
            "domAutomationController",
        ].filter((key) => key in window);
        const probeNotes = [];
        const realWebdriver = navigator.webdriver === true;
        const webdriver = realWebdriver || this.simulateBot;
        if (realWebdriver) {
            probeNotes.push("navigator.webdriver=true");
        }
        if (this.simulateBot) {
            probeNotes.push("fake webdriver injected by local debug toggle");
        }
        const descriptor = Object.getOwnPropertyDescriptor(Navigator.prototype, "webdriver");
        const webdriverDescriptorTampered = Boolean(descriptor) && (typeof descriptor?.get !== "function" || descriptor?.set !== undefined);
        if (webdriverDescriptorTampered) {
            probeNotes.push("navigator.webdriver descriptor looks modified");
        }
        if (automationGlobals.length > 0) {
            probeNotes.push(`automation globals: ${automationGlobals.join(",")}`);
        }
        const webgl = this.getWebGLInfo();
        const canvasId = await this.getCanvasFingerprint();
        const machineFlag = webdriver || webdriverDescriptorTampered || automationGlobals.length > 0;
        return {
            ua: navigator.userAgent,
            language: navigator.language,
            platform: navigator.platform,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "unknown",
            screen: `${window.screen.width}x${window.screen.height}x${window.screen.colorDepth}`,
            device_pixel_ratio: window.devicePixelRatio || 1,
            webdriver,
            webdriver_descriptor_tampered: webdriverDescriptorTampered,
            automation_globals: automationGlobals,
            canvas_id: canvasId,
            webgl_vendor: webgl.vendor,
            webgl_renderer: webgl.renderer,
            machine_flag: machineFlag,
            fake_webdriver: this.simulateBot,
            probe_notes: probeNotes,
        };
    }
    async getCanvasFingerprint() {
        const canvas = document.createElement("canvas");
        canvas.width = 180;
        canvas.height = 48;
        const ctx = canvas.getContext("2d");
        if (!ctx) {
            return "canvas-unavailable";
        }
        ctx.fillStyle = "#f5f7f2";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.font = "18px Georgia";
        ctx.fillStyle = "#26312d";
        ctx.fillText("VortexShield alpha omega 48921", 8, 30);
        ctx.strokeStyle = "#7b8f84";
        ctx.beginPath();
        ctx.moveTo(4, 38);
        ctx.bezierCurveTo(42, 2, 122, 58, 176, 12);
        ctx.stroke();
        const data = new TextEncoder().encode(canvas.toDataURL("image/png"));
        const digest = await crypto.subtle.digest("SHA-256", data);
        return this.arrayBufferToHex(digest).slice(0, 16);
    }
    getWebGLInfo() {
        const canvas = document.createElement("canvas");
        const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
        if (!gl) {
            return { vendor: "unavailable", renderer: "unavailable" };
        }
        const context = gl;
        const debugInfo = context.getExtension("WEBGL_debug_renderer_info");
        if (!debugInfo) {
            return {
                vendor: context.getParameter(context.VENDOR),
                renderer: context.getParameter(context.RENDERER),
            };
        }
        return {
            vendor: context.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
            renderer: context.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL),
        };
    }
    resolveContainer(container) {
        if (typeof container !== "string") {
            return container;
        }
        const element = document.querySelector(container);
        if (!element) {
            throw new Error(`Container not found: ${container}`);
        }
        return element;
    }
    arrayBufferToBase64(buffer) {
        const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        let binary = "";
        for (const byte of bytes) {
            binary += String.fromCharCode(byte);
        }
        return btoa(binary);
    }
    base64ToUint8Array(value) {
        const binary = atob(value);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i += 1) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
    arrayBufferToHex(buffer) {
        return [...new Uint8Array(buffer)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    }
}
function ensureSDKStyles() {
    if (document.getElementById(STYLE_ID)) {
        return;
    }
    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = `
    .vsec-card,
    .vsec-card * {
      box-sizing: border-box;
    }

    .vsec-card {
      --vsec-bg: #fbfcf8;
      --vsec-ink: #17211b;
      --vsec-muted: #6f7c73;
      --vsec-line: #dce5dc;
      --vsec-soft: #f1f6ef;
      --vsec-green: #18a05f;
      --vsec-green-2: #7bdc95;
      --vsec-red: #d94a3f;
      --vsec-blue: #3879d9;
      width: ${WIDGET_WIDTH}px;
      max-width: min(100%, 360px);
      border: 1px solid rgba(35, 54, 43, 0.12);
      border-radius: 8px;
      background:
        linear-gradient(180deg, rgba(255, 255, 255, 0.94), rgba(247, 250, 246, 0.98)),
        var(--vsec-bg);
      color: var(--vsec-ink);
      box-shadow:
        0 16px 34px rgba(23, 33, 27, 0.11),
        0 2px 8px rgba(23, 33, 27, 0.06);
      font-family: "Microsoft YaHei", "PingFang SC", "Segoe UI", sans-serif;
      overflow: hidden;
      user-select: none;
      position: relative;
      letter-spacing: 0;
    }

    .vsec-card[data-locale="en"] {
      width: min(360px, 100%);
    }

    .vsec-card::before {
      content: "";
      position: absolute;
      inset: 0;
      pointer-events: none;
      background:
        radial-gradient(circle at 18% 8%, rgba(24, 160, 95, 0.08), transparent 38%),
        radial-gradient(circle at 90% 28%, rgba(56, 121, 217, 0.06), transparent 34%);
    }

    .vsec-body {
      min-height: 84px;
      padding: 14px;
      position: relative;
      z-index: 1;
    }

    .vsec-footer {
      position: relative;
      z-index: 1;
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 6px;
      padding: 8px 12px 10px;
      border-top: 1px solid rgba(45, 66, 52, 0.08);
      color: #718078;
      font-size: 11px;
      line-height: 1;
      background: rgba(248, 251, 247, 0.7);
    }

    .vsec-brand-dot {
      width: 6px;
      height: 6px;
      border-radius: 999px;
      background: linear-gradient(135deg, var(--vsec-green), var(--vsec-blue));
      box-shadow: 0 0 0 3px rgba(24, 160, 95, 0.12);
    }

    .vsec-status-row {
      min-height: 58px;
      display: flex;
      align-items: center;
      gap: 12px;
      border-radius: 7px;
      padding: 10px;
      background: rgba(255, 255, 255, 0.62);
      border: 1px solid rgba(41, 61, 48, 0.08);
    }

    .vsec-status-row-airy {
      border-color: rgba(24, 160, 95, 0.16);
      background: rgba(246, 251, 246, 0.84);
    }

    .vsec-copy {
      min-width: 0;
      display: grid;
      gap: 3px;
    }

    .vsec-title {
      font-size: 15px;
      line-height: 1.25;
      font-weight: 750;
      color: var(--vsec-ink);
      overflow: hidden;
      text-overflow: ellipsis;
      overflow-wrap: anywhere;
      display: -webkit-box;
      -webkit-line-clamp: 2;
      -webkit-box-orient: vertical;
    }

    .vsec-subtitle {
      font-size: 12px;
      line-height: 1.35;
      color: var(--vsec-muted);
      overflow-wrap: anywhere;
    }

    .vsec-orb,
    .vsec-spinner,
    .vsec-checkmark,
    .vsec-failmark {
      width: 34px;
      height: 34px;
      flex: 0 0 34px;
      display: grid;
      place-items: center;
      border-radius: 999px;
    }

    .vsec-orb-idle {
      background: linear-gradient(135deg, #eef5ec, #ffffff);
      border: 1px solid var(--vsec-line);
      box-shadow: inset 0 0 0 5px #f8fbf6;
    }

    .vsec-spinner {
      border: 3px solid rgba(24, 160, 95, 0.16);
      border-top-color: var(--vsec-green);
      animation: vsec-spin 0.85s linear infinite;
    }

    .vsec-progress {
      height: 4px;
      margin-top: 12px;
      overflow: hidden;
      border-radius: 999px;
      background: #e8efe8;
    }

    .vsec-progress span {
      display: block;
      width: 42%;
      height: 100%;
      border-radius: inherit;
      background: linear-gradient(90deg, transparent, var(--vsec-green), var(--vsec-green-2));
      animation: vsec-progress 1.05s ease-in-out infinite;
    }

    .vsec-success-sweep {
      background: linear-gradient(110deg, rgba(24, 160, 95, 0.12), rgba(255, 255, 255, 0.9));
      border-color: rgba(24, 160, 95, 0.24);
      animation: vsec-success-in 0.42s cubic-bezier(0.2, 0.9, 0.2, 1) both;
    }

    .vsec-checkmark {
      background: linear-gradient(135deg, var(--vsec-green), #31c179);
      box-shadow: 0 8px 18px rgba(24, 160, 95, 0.24);
    }

    .vsec-checkmark svg {
      width: 20px;
      height: 20px;
      fill: none;
      stroke: #fff;
      stroke-width: 3;
      stroke-linecap: round;
      stroke-linejoin: round;
      stroke-dasharray: 30;
      stroke-dashoffset: 30;
      animation: vsec-check 0.36s 0.12s ease-out forwards;
    }

    .vsec-failmark {
      color: #fff;
      background: linear-gradient(135deg, var(--vsec-red), #f06c5f);
      font-weight: 900;
      box-shadow: 0 8px 18px rgba(217, 74, 63, 0.22);
    }

    .vsec-card.is-error {
      animation: vsec-shake 0.36s ease-in-out both;
      border-color: rgba(217, 74, 63, 0.35);
    }

    .vsec-checkbox-widget {
      width: 100%;
      min-height: 72px;
      display: grid;
      grid-template-columns: 40px 1fr 28px;
      align-items: center;
      gap: 12px;
      border: 1px solid rgba(42, 62, 50, 0.13);
      border-radius: 8px;
      background: linear-gradient(180deg, #ffffff, #f7faf6);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.9);
      cursor: pointer;
      color: var(--vsec-ink);
      padding: 12px;
      text-align: left;
      transition:
        border-color 180ms ease,
        box-shadow 180ms ease,
        transform 180ms ease;
    }

    .vsec-checkbox-widget:hover {
      border-color: rgba(24, 160, 95, 0.38);
      box-shadow: 0 10px 24px rgba(28, 44, 33, 0.08);
      transform: translateY(-1px);
    }

    .vsec-checkbox-mark {
      width: 32px;
      height: 32px;
      border-radius: 7px;
      border: 2px solid #8b9a90;
      background: #fff;
      position: relative;
    }

    .vsec-checkbox-widget.is-loading .vsec-checkbox-mark {
      border-color: var(--vsec-green);
      animation: vsec-spin 0.8s linear infinite;
      border-radius: 999px;
      border-right-color: transparent;
    }

    .vsec-checkbox-copy {
      min-width: 0;
      display: grid;
      gap: 3px;
    }

    .vsec-checkbox-copy strong {
      font-size: 15px;
      line-height: 1.2;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .vsec-checkbox-copy small {
      color: var(--vsec-muted);
      font-size: 12px;
      line-height: 1.3;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .vsec-checkbox-pulse {
      width: 10px;
      height: 10px;
      border-radius: 999px;
      justify-self: center;
      background: var(--vsec-green);
      box-shadow: 0 0 0 0 rgba(24, 160, 95, 0.3);
      animation: vsec-pulse 1.4s ease-out infinite;
    }

    .vsec-slider-shell {
      display: grid;
      gap: 10px;
    }

    .vsec-slider-prompt {
      color: #314039;
      font-size: 13px;
      font-weight: 700;
      line-height: 1.25;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .vsec-stage {
      width: 100%;
      max-width: 100%;
      position: relative;
      overflow: hidden;
      border-radius: 8px;
      border: 1px solid rgba(43, 61, 50, 0.14);
      background: #eef3ef;
      box-shadow:
        inset 0 1px 0 rgba(255, 255, 255, 0.76),
        0 10px 22px rgba(19, 34, 24, 0.1);
    }

    .vsec-bg {
      width: 100%;
      height: 100%;
      display: block;
      object-fit: cover;
      pointer-events: none;
    }

    .vsec-piece {
      position: absolute;
      left: 0;
      pointer-events: none;
      filter:
        drop-shadow(0 8px 10px rgba(8, 20, 12, 0.22))
        drop-shadow(0 1px 0 rgba(255, 255, 255, 0.58));
      will-change: transform;
      transform: translate3d(0, 0, 0);
      transition: transform 260ms cubic-bezier(0.18, 0.92, 0.16, 1);
    }

    .vsec-track {
      height: ${SLIDER_TRACK_HEIGHT}px;
      position: relative;
      border-radius: 8px;
      overflow: hidden;
      border: 1px solid rgba(42, 62, 50, 0.14);
      background:
        linear-gradient(180deg, #f9fbf8, #edf4ed);
      box-shadow: inset 0 1px 4px rgba(25, 40, 30, 0.08);
      touch-action: none;
    }

    .vsec-track-fill {
      position: absolute;
      inset: 0 auto 0 0;
      width: 22px;
      border-radius: inherit;
      background:
        linear-gradient(90deg, rgba(24, 160, 95, 0.16), rgba(24, 160, 95, 0.36));
      transition: width 220ms cubic-bezier(0.18, 0.92, 0.16, 1);
    }

    .vsec-card.is-dragging .vsec-track-fill {
      transition: none;
    }

    .vsec-track-text {
      position: absolute;
      inset: 0;
      display: grid;
      place-items: center;
      color: #718078;
      font-size: 13px;
      pointer-events: none;
      padding: 0 52px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .vsec-knob {
      position: absolute;
      inset: 0 auto 0 0;
      width: ${SLIDER_KNOB_SIZE}px;
      height: ${SLIDER_KNOB_SIZE}px;
      border: 0;
      border-right: 1px solid rgba(32, 52, 40, 0.16);
      border-radius: 8px;
      display: grid;
      place-items: center;
      cursor: grab;
      color: #fff;
      background:
        linear-gradient(135deg, #1a9d61, #27bd73);
      box-shadow:
        0 10px 20px rgba(24, 160, 95, 0.24),
        inset 0 1px 0 rgba(255, 255, 255, 0.26);
      transform: translate3d(0, 0, 0);
      transition:
        transform 260ms cubic-bezier(0.18, 0.92, 0.16, 1),
        box-shadow 180ms ease;
      touch-action: none;
    }

    .vsec-knob:active {
      cursor: grabbing;
    }

    .vsec-card.is-dragging .vsec-knob {
      transition: none;
      box-shadow:
        0 14px 26px rgba(24, 160, 95, 0.32),
        inset 0 1px 0 rgba(255, 255, 255, 0.32);
    }

    .vsec-knob span {
      width: 15px;
      height: 15px;
      border-top: 3px solid #fff;
      border-right: 3px solid #fff;
      transform: rotate(45deg);
      margin-left: -3px;
    }

    .vsec-card.is-verifying .vsec-knob span {
      width: 18px;
      height: 18px;
      border: 3px solid rgba(255, 255, 255, 0.42);
      border-top-color: #fff;
      border-radius: 999px;
      transform: none;
      margin: 0;
      animation: vsec-spin 0.7s linear infinite;
    }

    @keyframes vsec-spin {
      to { transform: rotate(360deg); }
    }

    @keyframes vsec-progress {
      0% { transform: translateX(-110%); }
      100% { transform: translateX(260%); }
    }

    @keyframes vsec-check {
      to { stroke-dashoffset: 0; }
    }

    @keyframes vsec-success-in {
      from {
        opacity: 0;
        transform: translateY(4px) scale(0.985);
      }
      to {
        opacity: 1;
        transform: translateY(0) scale(1);
      }
    }

    @keyframes vsec-pulse {
      0% { box-shadow: 0 0 0 0 rgba(24, 160, 95, 0.28); }
      70% { box-shadow: 0 0 0 10px rgba(24, 160, 95, 0); }
      100% { box-shadow: 0 0 0 0 rgba(24, 160, 95, 0); }
    }

    @keyframes vsec-shake {
      0%, 100% { transform: translateX(0); }
      18% { transform: translateX(-6px); }
      36% { transform: translateX(5px); }
      54% { transform: translateX(-3px); }
      72% { transform: translateX(2px); }
    }
  `;
    document.head.appendChild(style);
}
function isSliderChallenge(value) {
    if (!value || typeof value !== "object") {
        return false;
    }
    const challenge = value;
    return (challenge.captcha_type === "SLIDER" &&
        typeof challenge.captcha_token === "string" &&
        typeof challenge.bg_image === "string" &&
        typeof challenge.slider_piece_b64 === "string" &&
        typeof challenge.rsa_public_key === "string" &&
        typeof challenge.dimensions?.width === "number" &&
        typeof challenge.dimensions?.height === "number" &&
        typeof challenge.piece_size?.width === "number" &&
        typeof challenge.piece_size?.height === "number" &&
        typeof challenge.piece_y === "number");
}
function isCheckboxChallenge(value) {
    if (!value || typeof value !== "object") {
        return false;
    }
    const challenge = value;
    return (challenge.captcha_type === "CLICK_CHECKBOX" &&
        typeof challenge.captcha_token === "string" &&
        typeof challenge.rsa_public_key === "string");
}
function getClientX(event) {
    if ("touches" in event && event.touches.length > 0) {
        return event.touches[0].clientX;
    }
    if ("changedTouches" in event && event.changedTouches.length > 0) {
        return event.changedTouches[0].clientX;
    }
    return event.clientX;
}
function getClientY(event) {
    if ("touches" in event && event.touches.length > 0) {
        return event.touches[0].clientY;
    }
    if ("changedTouches" in event && event.changedTouches.length > 0) {
        return event.changedTouches[0].clientY;
    }
    return event.clientY;
}
function escapeHTML(value) {
    return value
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}
function escapeAttribute(value) {
    return escapeHTML(value);
}
window.CaptchaSDK = CaptchaSDK;
//# sourceMappingURL=vsec-sdk.js.map