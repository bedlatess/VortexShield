type CaptchaType = "SILENT" | "CLICK_CHECKBOX" | "SLIDER";
type TrackEventType = 0 | 1 | 2;
type LocaleCode = "zh" | "en";
type SDKState = "idle" | "prechecking" | "silent_passed" | "checkbox_ready" | "checkbox_verifying" | "slider_ready" | "slider_dragging" | "verifying" | "failed";
type TrackPoint = [x: number, y: number, timestamp: number, event_type: TrackEventType];
interface CaptchaDimensions {
    width: number;
    height: number;
}
interface SliderPieceSize {
    width: number;
    height: number;
}
interface CaptchaChallengeData {
    captcha_token: string;
    captcha_type: CaptchaType;
    bg_image: string;
    slider_piece_b64: string;
    prompt: string;
    dimensions: CaptchaDimensions;
    piece_size: SliderPieceSize;
    initial_x: number;
    piece_y: number;
    rsa_public_key: string;
}
interface CheckboxChallengeData {
    captcha_type: "CLICK_CHECKBOX";
    prompt: string;
    captcha_token: string;
    rsa_public_key: string;
}
type ChallengeData = CaptchaChallengeData | CheckboxChallengeData;
interface PrecheckKeyResponse {
    code: number;
    msg: string;
    data: {
        precheck_token: string;
        rsa_public_key: string;
    };
}
interface CaptchaChallengeResponse {
    code: number;
    msg: string;
    data: CaptchaChallengeData;
}
interface PrecheckResponse {
    code: number;
    msg: string;
    data: {
        action: "pass" | "challenge";
        captcha_type: CaptchaType;
        verify_signature: string | null;
        expires_in: number | null;
        risk_score: number;
        reason: string;
        challenge: ChallengeData | null;
        features?: Record<string, unknown> | null;
    };
}
interface CaptchaFingerprint {
    ua: string;
    language: string;
    platform: string;
    timezone: string;
    screen: string;
    device_pixel_ratio: number;
    webdriver: boolean;
    webdriver_descriptor_tampered: boolean;
    automation_globals: string[];
    canvas_id: string;
    webgl_vendor: string;
    webgl_renderer: string;
    machine_flag: boolean;
    fake_webdriver?: boolean;
    probe_notes: string[];
}
interface PrecheckPlainPayload {
    client_time: number;
    site_key: string;
    action: string;
    hostname: string;
    fingerprint: CaptchaFingerprint;
}
interface VerifyPlainPayload {
    client_time: number;
    site_key: string;
    action: string;
    hostname: string;
    captcha_token: string;
    captcha_type: CaptchaType;
    tracks: TrackPoint[];
    fingerprint: CaptchaFingerprint;
    slider_x?: number;
    checkbox_checked?: boolean;
}
interface EncryptedHybridPayload {
    version: "vsec-rsa-oaep-aes-gcm@phase5";
    alg: "RSA-OAEP-2048-SHA256+A256GCM";
    encrypted_key: string;
    encrypted_payload: {
        iv: string;
        ciphertext: string;
    };
}
interface CaptchaSubmitBundle {
    captcha_token: string;
    captcha_type: CaptchaType;
    plaintext: VerifyPlainPayload;
    encrypted: EncryptedHybridPayload;
}
interface CaptchaSDKOptions {
    container: HTMLElement | string;
    apiBaseUrl: string;
    siteKey: string;
    action?: string;
    simulateBot?: boolean;
    onSilentPass?: (signature: string, response: PrecheckResponse) => void;
    onChallengeRequired?: (challenge: ChallengeData, response: PrecheckResponse) => void;
    onReady?: (challenge: ChallengeData) => void;
    onComplete?: (bundle: CaptchaSubmitBundle) => void;
    onSuccess?: (signature: string, response: unknown) => void;
    onFailure?: (reason: string, response: unknown) => void;
    onError?: (error: unknown) => void;
}
declare const EVENT_MOVE: TrackEventType;
declare const EVENT_DOWN: TrackEventType;
declare const EVENT_UP: TrackEventType;
declare const STYLE_ID = "vsec-sdk-style";
declare const WIDGET_WIDTH = 320;
declare const SLIDER_TRACK_HEIGHT = 44;
declare const SLIDER_KNOB_SIZE = 44;
declare const I18N: {
    readonly zh: {
        readonly ariaLabel: "VortexShield 安全验证";
        readonly idleTitle: "等待安全验证";
        readonly idleSubtitle: "VortexShield 将自动选择验证方式";
        readonly verifying: "安全验证中...";
        readonly fetchingChallenge: "正在准备安全校验...";
        readonly refreshingChallenge: "正在更新校验流程...";
        readonly evaluating: "正在评估浏览器环境与会话完整性";
        readonly passed: "✅ 验证通过";
        readonly passedSubtitle: "行为可信，已完成无感校验";
        readonly verifyHuman: "验证您是真人";
        readonly checkboxPrompt: "请点击复选框完成安全确认";
        readonly sliderPrompt: "拖动滑块，使拼图与缺口完全重合";
        readonly sliderTrack: "按住滑块，拖动完成拼图";
        readonly sliderAria: "拖动滑块完成验证";
        readonly failedTitle: "验证失败，请重试";
        readonly failedSubtitle: "正在更新校验流程";
    };
    readonly en: {
        readonly ariaLabel: "VortexShield security verification";
        readonly idleTitle: "Waiting for verification";
        readonly idleSubtitle: "VortexShield will choose the verification mode";
        readonly verifying: "Verifying...";
        readonly fetchingChallenge: "Preparing verification...";
        readonly refreshingChallenge: "Updating verification flow...";
        readonly evaluating: "Checking browser environment and session integrity";
        readonly passed: "✅ Verification passed";
        readonly passedSubtitle: "Trusted behavior confirmed";
        readonly verifyHuman: "Verify you are human";
        readonly checkboxPrompt: "Click the checkbox to continue";
        readonly sliderPrompt: "Drag the slider to match the puzzle piece";
        readonly sliderTrack: "Hold and drag to complete the puzzle";
        readonly sliderAria: "Drag the slider to verify";
        readonly failedTitle: "Verification failed, try again";
        readonly failedSubtitle: "Updating verification flow";
    };
};
declare class CaptchaSDK {
    private readonly container;
    private readonly apiBaseUrl;
    private readonly siteKey;
    private readonly actionName;
    private readonly hostname;
    private readonly onSilentPass?;
    private readonly onChallengeRequired?;
    private readonly onReady?;
    private readonly onComplete?;
    private readonly onSuccess?;
    private readonly onFailure?;
    private readonly onError?;
    private readonly locale;
    private simulateBot;
    private root;
    private bodyEl;
    private footerEl;
    private state;
    private challenge;
    private checkboxChallenge;
    private startTime;
    private tracks;
    private cleanupCallbacks;
    private lastMoveSampleAt;
    private activePointerArea;
    private refreshTimer;
    private sliderStage;
    private sliderPiece;
    private sliderTrack;
    private sliderFill;
    private sliderKnob;
    private sliderX;
    private sliderDragStartClientX;
    private sliderDragStartX;
    private sliderMaxX;
    constructor(options: CaptchaSDKOptions);
    setSimulateBot(enabled: boolean): void;
    execute(): Promise<void>;
    loadChallenge(): Promise<void>;
    destroy(): void;
    private renderIdle;
    private renderSilentLoading;
    private renderSilentSuccess;
    private activateCheckboxChallenge;
    private activateSliderChallenge;
    private bindSliderEvents;
    private submitCheckboxVerify;
    private submitSliderVerify;
    private submitVerify;
    private failAndRefresh;
    private renderFailure;
    private fetchSliderChallenge;
    private fetchPrecheckKey;
    private buildURL;
    private computeSliderBounds;
    private applySliderX;
    private clampSliderX;
    private clampPieceY;
    private recordSampledEvent;
    private recordPointerEvent;
    private recordSampledSyntheticTrack;
    private recordSyntheticTrack;
    private toLocalPoint;
    private resetRuntimeState;
    private resetInteractionState;
    private normalizeCheckboxChallenge;
    private detectLocale;
    private t;
    private localizedPrompt;
    private setState;
    private handleFatalError;
    private clearRefreshTimer;
    private encryptHybridPayload;
    private importRsaPublicKey;
    private collectFingerprint;
    private getCanvasFingerprint;
    private getWebGLInfo;
    private resolveContainer;
    private arrayBufferToBase64;
    private base64ToUint8Array;
    private arrayBufferToHex;
}
declare function ensureSDKStyles(): void;
declare function isSliderChallenge(value: unknown): value is CaptchaChallengeData;
declare function isCheckboxChallenge(value: unknown): value is CheckboxChallengeData;
declare function getClientX(event: MouseEvent | TouchEvent): number;
declare function getClientY(event: MouseEvent | TouchEvent): number;
declare function escapeHTML(value: string): string;
declare function escapeAttribute(value: string): string;
interface Window {
    CaptchaSDK: typeof CaptchaSDK;
}
