function getCookie(name) {
  const cookieValue = document.cookie
    .split("; ")
    .find((row) => row.startsWith(name + "="));
  return cookieValue ? decodeURIComponent(cookieValue.split("=")[1]) : "";
}

function colorByRisk(level) {
  if (level === "high") return "#b91c1c";
  if (level === "medium") return "#ca8a04";
  return "#15803d";
}

function decisionLabel(decision) {
  if (decision === "allow") return "allow: стандартный вход";
  if (decision === "require_mfa")
    return "require_mfa: требуется дополнительное подтверждение";
  if (decision === "block") return "block: вход ограничен";
  return decision || "-";
}

function renderResult(data) {
  const score = Number(data.risk_score || 0);
  const level = data.risk_level || "-";

  document.getElementById("risk-score").textContent = score.toFixed(2);
  document.getElementById("risk-level").textContent = level;
  document.getElementById("risk-level").style.background = colorByRisk(level);
  document.getElementById("risk-level").style.color = "#fff";
  document.getElementById("risk-decision").textContent = decisionLabel(
    data.decision,
  );

  const progress = document.getElementById("risk-progress");
  progress.style.width = `${Math.min(100, Math.round(score * 100))}%`;
  progress.style.background = colorByRisk(level);

  const factorTable = document.getElementById("factor-table");
  factorTable.innerHTML = "";
  const factors = data.factor_scores || {};
  const rows = [
    ["Пространственно-временной", factors.spatio_temporal],
    ["Устройство и браузер", factors.device_browser],
    ["Сетевой", factors.network],
    ["Поведенческий", factors.behavioral],
  ];
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${row[0]}</td><td>${Number(row[1] || 0).toFixed(2)}</td>`;
    factorTable.appendChild(tr);
  });

  const explanations = document.getElementById("explanations");
  explanations.innerHTML = "";
  (data.explanation || []).forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    explanations.appendChild(li);
  });

  if (data.decision === "require_mfa") {
    const mfaBox = document.getElementById("mfa-box");
    mfaBox.classList.remove("hidden");
    mfaBox.dataset.challengeId = data.challenge_id;
    if (data.demo_mfa_code) {
      document.getElementById("demo-code").textContent =
        `Demo MFA code (for local prototype): ${data.demo_mfa_code}`;
    }
  }
}

async function bindMfaForm() {
  const form = document.getElementById("mfa-form");
  if (!form) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const mfaBox = document.getElementById("mfa-box");
    const message = document.getElementById("mfa-message");

    const payload = {
      challenge_id: Number(mfaBox.dataset.challengeId),
      code: form.code.value,
    };

    const response = await fetch("/api/auth/verify-mfa/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": getCookie("csrftoken"),
      },
      body: JSON.stringify(payload),
    });
    const data = await response.json();

    if (!response.ok) {
      message.textContent = data.message || "Ошибка MFA";
      message.style.color = "#b91c1c";
      return;
    }

    message.textContent = "MFA успешно подтверждено. Переход в профиль...";
    message.style.color = "#15803d";
    setTimeout(() => {
      window.location.href = "/profile/";
    }, 900);
  });
}

(function initResultPage() {
  const raw = sessionStorage.getItem("authResult");
  if (!raw) {
    document.getElementById("result-card").innerHTML =
      "<p>Нет данных о попытке входа. Выполните вход на главной странице.</p>";
    return;
  }
  const data = JSON.parse(raw);
  renderResult(data);
  bindMfaForm();
})();
