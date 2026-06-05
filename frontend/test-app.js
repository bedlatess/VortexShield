(function () {
  const startButton = document.querySelector("#start-btn");
  const fakeBotToggle = document.querySelector("#fake-bot");
  const statusEl = document.querySelector("#debug-status");
  const outputEl = document.querySelector("#debug-output");

  const sdk = new window.CaptchaSDK({
    container: "#captcha-root",
    apiBaseUrl: "http://127.0.0.1:48921",
    simulateBot: false,
    onSilentPass(signature, response) {
      console.log("Silent Precheck Pass", response);
      statusEl.className = "is-success";
      statusEl.textContent = "验证成功，行为可信";
      outputEl.textContent = JSON.stringify(
        {
          mode: "silent-pass",
          captcha_type: response.data.captcha_type,
          verify_signature: signature,
          response,
        },
        null,
        2,
      );
    },
    onChallengeRequired(challenge, response) {
      console.log("Step-up Challenge Required", response);
      statusEl.className = "is-loading";
      statusEl.textContent = `需要进一步验证：${response.data.captcha_type}`;
      outputEl.textContent = JSON.stringify(
        {
          mode: "challenge-required",
          captcha_type: response.data.captcha_type,
          captcha_token: challenge.captcha_token || null,
          prompt: challenge.prompt,
          response,
        },
        null,
        2,
      );
    },
    onComplete(bundle) {
      console.group("VortexShield Verify Payload");
      console.log("Captcha Type", bundle.captcha_type);
      console.log("Plain Payload", bundle.plaintext);
      console.log("Encrypted Payload", bundle.encrypted);
      console.groupEnd();
      outputEl.textContent = JSON.stringify(
        {
          mode: "payload-ready",
          captcha_type: bundle.captcha_type,
          slider_x: bundle.plaintext.slider_x ?? null,
          plaintext: bundle.plaintext,
          encrypted: bundle.encrypted,
        },
        null,
        2,
      );
    },
    onSuccess(signature, response) {
      console.log("Verify Success", response);
      statusEl.className = "is-success";
      statusEl.textContent = "验证成功，行为可信";
      outputEl.textContent = JSON.stringify(
        {
          mode: "verified",
          verify_signature: signature,
          response,
        },
        null,
        2,
      );
    },
    onFailure(reason, response) {
      console.warn("Verify Failure", reason, response);
      statusEl.className = "is-error";
      statusEl.textContent = `验证失败：${reason}`;
      outputEl.textContent = JSON.stringify({ reason, response }, null, 2);
    },
    onError(error) {
      console.error("VortexShield SDK error", error);
      statusEl.className = "is-error";
      statusEl.textContent = `错误：${error instanceof Error ? error.message : String(error)}`;
    },
  });

  startButton.addEventListener("click", async () => {
    startButton.disabled = true;
    sdk.setSimulateBot(fakeBotToggle.checked);
    statusEl.className = "is-loading";
    statusEl.textContent = "安全验证中...";
    outputEl.textContent = "{}";
    try {
      await sdk.execute();
    } finally {
      startButton.disabled = false;
    }
  });
})();
