function getCookie(name) {
  const cookieValue = document.cookie
    .split("; ")
    .find((row) => row.startsWith(name + "="));
  return cookieValue ? decodeURIComponent(cookieValue.split("=")[1]) : "";
}

function getCanvasFingerprint() {
  try {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    ctx.textBaseline = "top";
    ctx.font = "14px Arial";
    ctx.fillText("adaptive-auth-fp", 2, 2);
    return canvas.toDataURL();
  } catch (e) {
    return "not_available";
  }
}

function getWebGLFingerprint() {
  try {
    const canvas = document.createElement("canvas");
    const gl =
      canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
    if (!gl) {
      return "not_available";
    }
    const debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
    if (!debugInfo) {
      return "limited";
    }
    return gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || "unknown";
  } catch (e) {
    return "not_available";
  }
}

function collectFingerprint() {
  return {
    userAgent: navigator.userAgent || "",
    language: navigator.language || "",
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "",
    screenResolution: `${window.screen.width}x${window.screen.height}`,
    platform: navigator.platform || "",
    deviceMemory: navigator.deviceMemory || null,
    hardwareConcurrency: navigator.hardwareConcurrency || null,
    canvas: getCanvasFingerprint(),
    webgl: getWebGLFingerprint(),
    localStorage: !!window.localStorage,
    sessionStorage: !!window.sessionStorage,
  };
}

let formStart = Date.now();
let keyTimes = [];
let corrections = 0;

document.addEventListener("keydown", (event) => {
  keyTimes.push(Date.now());
  if (event.key === "Backspace" || event.key === "Delete") {
    corrections += 1;
  }
});

function collectBehavior() {
  const formFillMs = Date.now() - formStart;
  let avgKeyDelayMs = 200;
  if (keyTimes.length > 1) {
    let sum = 0;
    for (let i = 1; i < keyTimes.length; i += 1) {
      sum += keyTimes[i] - keyTimes[i - 1];
    }
    avgKeyDelayMs = Math.round(sum / (keyTimes.length - 1));
  }
  return {
    formFillMs,
    avgKeyDelayMs,
    corrections,
  };
}

async function handleRegisterForm() {
  const form = document.getElementById("register-form");
  if (!form) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const message = document.getElementById("register-message");
    message.textContent = "Отправка...";

    const payload = {
      username: form.username.value,
      email: form.email.value,
      password: form.password.value,
    };

    const response = await fetch("/api/auth/register/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": getCookie("csrftoken"),
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json();
    if (!response.ok) {
      message.textContent = data.detail || JSON.stringify(data);
      message.style.color = "#b91c1c";
      return;
    }

    message.textContent = "Регистрация успешна. Перейдите ко входу.";
    message.style.color = "#15803d";
  });
}

async function handleLoginForm() {
  const form = document.getElementById("login-form");
  if (!form) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const message = document.getElementById("login-message");
    message.textContent = "Проверка...";

    const now = new Date();
    const payload = {
      identifier: form.identifier.value,
      password: form.password.value,
      country: form.country.value,
      city: form.city.value,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      localHour: now.getHours(),
      localWeekday: now.getDay(),
      provider: form.provider.value,
      vpn: form.vpn.checked,
      ipReputation: Number(form.ipReputation.value || 0.6),
      fingerprint: collectFingerprint(),
      behavior: collectBehavior(),
    };

    try {
      const response = await fetch("/api/auth/login/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": getCookie("csrftoken"),
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();
      if (!response.ok) {
        message.textContent = data.message || "Ошибка входа";
        message.style.color = "#b91c1c";
        return;
      }

      sessionStorage.setItem("authResult", JSON.stringify(data));
      window.location.href = "/result/";
    } catch (error) {
      message.textContent = "Сетевая ошибка";
      message.style.color = "#b91c1c";
    }
  });
}

handleRegisterForm();
handleLoginForm();
