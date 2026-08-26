const form = document.querySelector("#scanForm");
const domainForm = document.querySelector("#domainForm");
const scanButton = document.querySelector("#scanButton");
const cancelScanButton = document.querySelector("#cancelScanButton");
const addDomainButton = document.querySelector("#addDomainButton");
const clearButton = document.querySelector("#clearButton");
const testEmailButton = document.querySelector("#testEmailButton");
const sendManualEmailButton = document.querySelector("#sendManualEmailButton");
const manualEmailRecipients = document.querySelector("#manualEmailRecipients");
const manualEmailStatus = document.querySelector("#manualEmailStatus");
const scanState = document.querySelector("#scanState");
const authUser = document.querySelector("#authUser");
const authUserName = document.querySelector("#authUserName");
const logoutButton = document.querySelector("#logoutButton");
const progress = document.querySelector("#progress");
const summary = document.querySelector("#summary");
const targetLabel = document.querySelector("#targetLabel");
const monitorLabel = document.querySelector("#monitorLabel");
const domainList = document.querySelector("#domainList");
const refreshDomains = document.querySelector("#refreshDomains");
const openDomainPanel = document.querySelector("#openDomainPanel");
const closeDomainPanel = document.querySelector("#closeDomainPanel");
const domainPanel = document.querySelector("#domainPanel");
const domainOverlay = document.querySelector("#domainOverlay");
const navItems = document.querySelectorAll(".nav-item");
const views = document.querySelectorAll(".view");
const tabs = document.querySelectorAll(".tab");
const appScanForm = document.querySelector("#appScanForm");
const appScanButton = document.querySelector("#appScanButton");
const cancelAppScanButton = document.querySelector("#cancelAppScanButton");
const appProgress = document.querySelector("#appProgress");
const appSummary = document.querySelector("#appSummary");
const appFindings = document.querySelector("#appFindings");
const appTargetLabel = document.querySelector("#appTargetLabel");
const panels = {
  findings: document.querySelector("#tab-findings"),
  pages: document.querySelector("#tab-pages"),
  waf: document.querySelector("#tab-waf")
};
const metrics = {
  pages: document.querySelector("#metricPages"),
  high: document.querySelector("#metricHigh"),
  medium: document.querySelector("#metricMedium"),
  low: document.querySelector("#metricLow"),
  subdomains: document.querySelector("#metricSubdomains"),
  domains: document.querySelector("#metricDomains"),
  online: document.querySelector("#metricOnline"),
  down: document.querySelector("#metricDown"),
  weekly: document.querySelector("#metricWeekly"),
  riskScore: document.querySelector("#riskScore"),
  dashHigh: document.querySelector("#dashHigh"),
  dashMedium: document.querySelector("#dashMedium"),
  dashLow: document.querySelector("#dashLow"),
  dashInfo: document.querySelector("#dashInfo"),
  barHigh: document.querySelector("#barHigh"),
  barMedium: document.querySelector("#barMedium"),
  barLow: document.querySelector("#barLow"),
  barInfo: document.querySelector("#barInfo"),
  uptimeGauge: document.querySelector("#uptimeGauge"),
  uptimeValue: document.querySelector("#uptimeValue"),
  healthyTargets: document.querySelector("#healthyTargets"),
  unknownTargets: document.querySelector("#unknownTargets"),
  avgLatency: document.querySelector("#avgLatency"),
  latencySparkline: document.querySelector("#latencySparkline"),
  nextCheck: document.querySelector("#nextCheck"),
  nextScan: document.querySelector("#nextScan"),
  runningScans: document.querySelector("#runningScans")
};
const exportButtons = {
  json: document.querySelector("#exportJson"),
  csv: document.querySelector("#exportCsv"),
  html: document.querySelector("#exportHtml")
};
const appExportButtons = {
  json: document.querySelector("#appExportJson"),
  csv: document.querySelector("#appExportCsv"),
  html: document.querySelector("#appExportHtml")
};

let currentReport = null;
let currentAppReport = null;
let currentStore = null;
let currentManualJobId = null;
let currentManualCompletedJobId = null;
let currentAppJobId = null;

initSession();

async function initSession() {
  try {
    const response = await apiFetch("/api/auth/session");
    const data = await response.json();
    if (data.authenticated && data.user) {
      authUser?.classList.remove("hidden");
      if (authUserName) authUserName.textContent = data.user.displayName || data.user.username;
    }
  } catch {
    // apiFetch already redirects expired sessions.
  }
}

async function apiFetch(url, options) {
  const response = await fetch(url, options);
  if (response.status === 401) {
    window.location.href = "/login";
    throw new Error("Sessao expirada. Faca login novamente.");
  }
  return response;
}

navItems.forEach((item) => {
  item.addEventListener("click", () => showView(item.dataset.view));
});

logoutButton?.addEventListener("click", async () => {
  await apiFetch("/api/auth/logout", { method: "POST" }).catch(() => {});
  window.location.href = "/login";
});

openDomainPanel.addEventListener("click", () => setDomainPanel(true));
closeDomainPanel.addEventListener("click", () => setDomainPanel(false));
domainOverlay.addEventListener("click", () => setDomainPanel(false));
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") setDomainPanel(false);
});

domainForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = {
    target: document.querySelector("#domainTarget").value,
    maxPages: document.querySelector("#domainMaxPages").value,
    timeoutMs: document.querySelector("#domainTimeoutMs").value,
    emailRecipients: document.querySelector("#domainEmailRecipients").value,
    weeklyEmailEnabled: document.querySelector("#domainWeeklyEmailEnabled").checked,
    includeSubdomains: document.querySelector("#domainIncludeSubdomains").checked,
    activeWafProbe: document.querySelector("#domainActiveWafProbe").checked,
    followPaths: false
  };

  addDomainButton.disabled = true;
  addDomainButton.textContent = "Cadastrando...";
  monitorLabel.textContent = "Cadastrando dominio e iniciando o primeiro scan em segundo plano...";
  try {
    const response = await apiFetch("/api/domains", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Falha ao cadastrar.");
    domainForm.reset();
    document.querySelector("#domainIncludeSubdomains").checked = true;
    document.querySelector("#domainWeeklyEmailEnabled").checked = true;
    renderStore(data.store);
    setDomainPanel(false);
    monitorLabel.textContent = "Dominio cadastrado. O primeiro scan esta rodando em segundo plano.";
  } catch (error) {
    monitorLabel.textContent = error.message || "Falha ao cadastrar dominio.";
  } finally {
    addDomainButton.disabled = false;
    addDomainButton.textContent = "Cadastrar monitoramento";
  }
});

refreshDomains.addEventListener("click", () => loadDomains());

domainList.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const { action, id } = button.dataset;
  button.disabled = true;
  try {
    const method = action === "delete" ? "DELETE" : "POST";
    const path = action === "delete" ? `/api/domains/${id}` : `/api/domains/${id}/${action}`;
    const response = await apiFetch(path, { method });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Operacao falhou.");
    renderStore(data.store || { domains: data.domain ? [data.domain] : [] });
    if (action === "scan" && data.domain?.reports?.length) {
      const latest = data.domain.reports[data.domain.reports.length - 1].report;
      currentReport = latest;
      renderReport(latest);
      enableExports(true);
      showView("manual");
    }
  } catch (error) {
    monitorLabel.textContent = error.message || "Operacao falhou.";
  } finally {
    button.disabled = false;
  }
});

function showView(name) {
  navItems.forEach((item) => item.classList.toggle("active", item.dataset.view === name));
  views.forEach((view) => view.classList.toggle("active-view", view.id === `view-${name}`));
}

function setDomainPanel(open) {
  domainPanel.classList.toggle("hidden", !open);
  domainOverlay.classList.toggle("hidden", !open);
  domainPanel.setAttribute("aria-hidden", String(!open));
  if (open) document.querySelector("#domainTarget").focus();
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = {
    target: document.querySelector("#target").value,
    maxPages: document.querySelector("#maxPages").value,
    timeoutMs: document.querySelector("#timeoutMs").value,
    includeSubdomains: document.querySelector("#includeSubdomains").checked,
    followPaths: document.querySelector("#followPaths").checked,
    activeWafProbe: document.querySelector("#activeWafProbe").checked
  };

  setLoading(true);
  try {
    const data = await runCancelableScan(payload, {
      setJobId: (id) => { currentManualJobId = id; },
      onStatus: (job) => { targetLabel.textContent = `Scan em andamento - ${job.status}`; }
    });
    currentReport = data.report;
    currentManualCompletedJobId = data.id;
    renderReport(data.report);
    enableExports(true);
    updateManualEmailButton();
  } catch (error) {
    summary.classList.remove("empty");
    summary.textContent = error.message || "Falha inesperada.";
    enableExports(false);
    currentManualCompletedJobId = null;
    updateManualEmailButton();
  } finally {
    currentManualJobId = null;
    setLoading(false);
  }
});

cancelScanButton.addEventListener("click", async () => {
  if (!currentManualJobId) return;
  cancelScanButton.disabled = true;
  await apiFetch(`/api/manual-scans/${currentManualJobId}`, { method: "DELETE" });
});

appScanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = {
    target: document.querySelector("#appTarget").value,
    maxPages: 40,
    timeoutMs: document.querySelector("#appTimeoutMs").value,
    includeSubdomains: false,
    followPaths: document.querySelector("#appFollowPaths").checked,
    activeWafProbe: document.querySelector("#appActiveWafProbe").checked,
    appProfile: document.querySelector("#appProfile").value
  };

  setAppLoading(true);
  try {
    const data = await runCancelableScan(payload, {
      setJobId: (id) => { currentAppJobId = id; },
      onStatus: (job) => { appTargetLabel.textContent = `Teste em andamento - ${job.status}`; }
    });
    currentAppReport = data.report;
    renderAppReport(data.report);
    enableAppExports(true);
  } catch (error) {
    appSummary.className = "summary";
    appSummary.textContent = error.message || "Falha inesperada.";
    enableAppExports(false);
  } finally {
    currentAppJobId = null;
    setAppLoading(false);
  }
});

cancelAppScanButton.addEventListener("click", async () => {
  if (!currentAppJobId) return;
  cancelAppScanButton.disabled = true;
  await apiFetch(`/api/manual-scans/${currentAppJobId}`, { method: "DELETE" });
});

clearButton.addEventListener("click", () => {
  currentReport = null;
  currentManualCompletedJobId = null;
  form.reset();
  metrics.pages.textContent = "0";
  metrics.high.textContent = "0";
  metrics.medium.textContent = "0";
  metrics.low.textContent = "0";
  metrics.subdomains.textContent = "0";
  targetLabel.textContent = "Nenhum dominio escaneado ainda.";
  summary.className = "summary empty";
  summary.textContent = "Informe o dominio e inicie o scan para ver os achados.";
  panels.findings.innerHTML = "";
  panels.pages.innerHTML = "";
  panels.waf.innerHTML = "";
  enableExports(false);
  updateManualEmailButton();
  manualEmailStatus.textContent = "Use o teste para validar SMTP; o envio do relatorio fica disponivel apos o scan finalizar.";
});

manualEmailRecipients.addEventListener("input", () => updateManualEmailButton());

testEmailButton.addEventListener("click", async () => {
  await sendEmailAction({
    button: testEmailButton,
    path: "/api/email/test",
    loadingText: "Testando...",
    successText: "E-mail de teste enviado."
  });
});

sendManualEmailButton.addEventListener("click", async () => {
  if (!currentManualCompletedJobId) return;
  await sendEmailAction({
    button: sendManualEmailButton,
    path: `/api/manual-scans/${currentManualCompletedJobId}/email`,
    loadingText: "Enviando...",
    successText: "Relatorio manual enviado por e-mail."
  });
});

loadDomains();
setInterval(loadDomains, 30_000);

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    tabs.forEach((item) => item.classList.remove("active"));
    tab.classList.add("active");
    Object.values(panels).forEach((panel) => panel.classList.add("hidden"));
    panels[tab.dataset.tab].classList.remove("hidden");
  });
});

exportButtons.json.addEventListener("click", () => {
  download("relatorio-scan-dominio.json", "application/json", JSON.stringify(currentReport, null, 2));
});

exportButtons.csv.addEventListener("click", () => {
  download("achados-scan-dominio.csv", "text/csv", findingsToCsv(currentReport));
});

exportButtons.html.addEventListener("click", () => {
  download("relatorio-scan-dominio.html", "text/html", reportToHtml(currentReport));
});

appExportButtons.json.addEventListener("click", () => {
  downloadReport(currentAppReport, "relatorio-aplicacao.json", "application/json", JSON.stringify(currentAppReport, null, 2));
});

appExportButtons.csv.addEventListener("click", () => {
  downloadReport(currentAppReport, "achados-aplicacao.csv", "text/csv", findingsToCsv(currentAppReport));
});

appExportButtons.html.addEventListener("click", () => {
  downloadReport(currentAppReport, "relatorio-aplicacao.html", "text/html", reportToHtml(currentAppReport));
});

function setLoading(isLoading) {
  scanButton.disabled = isLoading;
  scanButton.textContent = isLoading ? "Escaneando..." : "Iniciar scan";
  cancelScanButton.classList.toggle("hidden", !isLoading);
  cancelScanButton.disabled = !isLoading;
  scanState.textContent = isLoading ? "Em execucao" : "Pronto";
  progress.classList.toggle("hidden", !isLoading);
}

function setAppLoading(isLoading) {
  appScanButton.disabled = isLoading;
  appScanButton.textContent = isLoading ? "Testando..." : "Testar aplicacao";
  cancelAppScanButton.classList.toggle("hidden", !isLoading);
  cancelAppScanButton.disabled = !isLoading;
  appProgress.classList.toggle("hidden", !isLoading);
}

function enableExports(enabled) {
  Object.values(exportButtons).forEach((button) => {
    button.disabled = !enabled;
  });
  updateManualEmailButton();
}

function enableAppExports(enabled) {
  Object.values(appExportButtons).forEach((button) => {
    button.disabled = !enabled;
  });
}

async function runCancelableScan(payload, hooks) {
  const start = await apiFetch("/api/manual-scans", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload)
  });
  const created = await start.json();
  if (!start.ok) throw new Error(created.error || "Falha ao iniciar scan.");
  hooks.setJobId(created.id);

  while (true) {
    await wait(900);
    const response = await apiFetch(`/api/manual-scans/${created.id}`);
    const job = await response.json();
    if (!response.ok) throw new Error(job.error || "Falha ao consultar scan.");
    hooks.onStatus?.(job);
    if (job.status === "completed") return job;
    if (job.status === "cancelled") throw new Error("Scan cancelado pelo usuario.");
    if (job.status === "failed") throw new Error(job.error || "Scan falhou.");
  }
}

async function sendEmailAction({ button, path, loadingText, successText }) {
  const originalText = button.textContent;
  const recipients = manualEmailRecipients.value;
  button.disabled = true;
  button.textContent = loadingText;
  manualEmailStatus.textContent = "Enviando mensagem...";
  try {
    const response = await apiFetch(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ recipients })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Falha ao enviar e-mail.");
    manualEmailStatus.textContent = `${successText} Destinatarios: ${data.recipients.join(", ")}.`;
  } catch (error) {
    manualEmailStatus.textContent = error.message || "Falha ao enviar e-mail.";
  } finally {
    button.textContent = originalText;
    button.disabled = false;
    updateManualEmailButton();
  }
}

function updateManualEmailButton() {
  const hasRecipients = Boolean(manualEmailRecipients?.value.trim());
  sendManualEmailButton.disabled = !currentReport || !currentManualCompletedJobId || !hasRecipients;
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function loadDomains() {
  try {
    const response = await apiFetch("/api/domains");
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Falha ao carregar monitoramento.");
    renderStore(data);
  } catch (error) {
    monitorLabel.textContent = error.message || "Falha ao carregar monitoramento.";
  }
}

function renderStore(store) {
  currentStore = store;
  const domains = store.domains || [];
  const rootDomains = domains.filter((domain) => domain.kind !== "subdomain");
  const online = domains.filter((domain) => domain.lastStatus?.ok).length;
  const down = domains.filter((domain) => domain.lastStatus && !domain.lastStatus.ok).length;
  const weekly = domains.filter((domain) => domain.lastScanSummary).length;
  const unknown = domains.filter((domain) => !domain.lastStatus).length;
  const runningScans = domains.filter((domain) => domain.runningScan).length;
  const latencyValues = domains
    .flatMap((domain) => domain.history || [])
    .filter((item) => Number.isFinite(Number(item.responseTimeMs)))
    .slice(-30)
    .map((item) => Number(item.responseTimeMs));
  const avgLatency = latencyValues.length
    ? Math.round(latencyValues.reduce((sum, value) => sum + value, 0) / latencyValues.length)
    : 0;
  const severity = aggregateSeverity(domains);
  const maxSeverity = Math.max(1, severity.high, severity.medium, severity.low, severity.info);
  const uptime = domains.length ? Math.round((online / domains.length) * 100) : 0;
  const nextCheckAt = getNextDate(domains, "nextStatusAt");
  const nextScanAt = getNextDate(domains, "nextScanAt");
  metrics.domains.textContent = domains.length;
  metrics.online.textContent = online;
  metrics.down.textContent = down;
  metrics.weekly.textContent = weekly;
  metrics.riskScore.textContent = severity.high * 10 + severity.medium * 4 + severity.low;
  metrics.dashHigh.textContent = severity.high;
  metrics.dashMedium.textContent = severity.medium;
  metrics.dashLow.textContent = severity.low;
  metrics.dashInfo.textContent = severity.info;
  metrics.barHigh.style.width = `${Math.round((severity.high / maxSeverity) * 100)}%`;
  metrics.barMedium.style.width = `${Math.round((severity.medium / maxSeverity) * 100)}%`;
  metrics.barLow.style.width = `${Math.round((severity.low / maxSeverity) * 100)}%`;
  metrics.barInfo.style.width = `${Math.round((severity.info / maxSeverity) * 100)}%`;
  metrics.uptimeGauge.style.setProperty("--value", uptime);
  metrics.uptimeValue.textContent = `${uptime}%`;
  metrics.healthyTargets.textContent = online;
  metrics.unknownTargets.textContent = unknown;
  metrics.avgLatency.textContent = latencyValues.length ? `${avgLatency} ms` : "-";
  metrics.latencySparkline.innerHTML = renderSparkline(latencyValues);
  metrics.nextCheck.textContent = nextCheckAt ? formatDate(nextCheckAt) : "-";
  metrics.nextScan.textContent = nextScanAt ? formatDate(nextScanAt) : "-";
  metrics.runningScans.textContent = runningScans;
  monitorLabel.textContent = domains.length
    ? `${domains.length} alvo${domains.length === 1 ? "" : "s"} monitorado${domains.length === 1 ? "" : "s"}, incluindo subdominios`
    : "Nenhum dominio cadastrado para monitoramento.";
  if (!domains.length) {
    domainList.innerHTML = `<div class="summary empty">Cadastre um dominio para iniciar checks horarios e scans semanais.</div>`;
    return;
  }
  domainList.innerHTML = rootDomains.map((domain) => {
    const children = domains
      .filter((item) => item.parentId === domain.id)
      .sort((a, b) => a.label.localeCompare(b.label));
    return renderDomainCard(domain, children);
  }).join("");
}

function aggregateSeverity(domains) {
  return domains.reduce((total, domain) => {
    const summary = domain.lastScanSummary?.summary;
    if (!summary) return total;
    total.high += Number(summary.high || 0);
    total.medium += Number(summary.medium || 0);
    total.low += Number(summary.low || 0);
    total.info += Number(summary.info || 0);
    return total;
  }, { high: 0, medium: 0, low: 0, info: 0 });
}

function getNextDate(domains, field) {
  const dates = domains
    .map((domain) => Date.parse(domain[field]))
    .filter((value) => Number.isFinite(value))
    .sort((a, b) => a - b);
  return dates.length ? new Date(dates[0]).toISOString() : "";
}

function renderSparkline(values) {
  if (!values.length) {
    return `<div class="spark-empty">Sem historico suficiente</div>`;
  }
  const max = Math.max(...values, 1);
  return values.map((value) => {
    const height = Math.max(8, Math.round((value / max) * 72));
    const tone = value > 1500 ? "hot" : value > 700 ? "warm" : "cool";
    return `<span class="spark-bar ${tone}" style="height:${height}px" title="${value} ms"></span>`;
  }).join("");
}

function renderDomainCard(domain, children = []) {
  const last = domain.lastStatus;
  const scan = domain.lastScanSummary;
  const emailDelivery = domain.emailDeliveries?.[domain.emailDeliveries.length - 1];
  const recipients = domain.emailRecipients || [];
  const statusClass = !last ? "pending" : last.ok ? "ok" : "down";
  const statusText = !last ? "Aguardando check" : last.ok ? `Online HTTP ${last.status}` : `Indisponivel${last.status ? ` HTTP ${last.status}` : ""}`;
  return `
    <article class="domain-card">
      <header>
        <div>
          <h3>${escapeHtml(domain.label || domain.target)}</h3>
          <p>${escapeHtml(domain.target)}${children.length ? ` - ${children.length} subdominio${children.length === 1 ? "" : "s"} monitorado${children.length === 1 ? "" : "s"}` : ""}</p>
        </div>
        <span class="status-dot ${statusClass}">${escapeHtml(statusText)}</span>
      </header>
      <dl class="kv">
        <dt>Ultimo check</dt><dd>${last ? `${formatDate(last.checkedAt)} - ${last.responseTimeMs} ms${last.error ? ` - ${last.error}` : ""}` : "-"}</dd>
        <dt>Proximo check</dt><dd>${formatDate(domain.nextStatusAt)}</dd>
        <dt>Ultimo scan</dt><dd>${scan ? `${formatDate(scan.finishedAt)} - ${scan.summary.findings} achados em ${scan.summary.pagesScanned} URLs` : "-"}</dd>
        <dt>Proximo scan</dt><dd>${formatDate(domain.nextScanAt)}</dd>
        <dt>Relatorio semanal</dt><dd>${escapeHtml(formatEmailConfig(domain, recipients, emailDelivery))}</dd>
      </dl>
      <div class="domain-actions">
        <button type="button" data-action="check" data-id="${escapeHtml(domain.id)}" ${domain.runningStatus ? "disabled" : ""}>Checar agora</button>
        <button type="button" data-action="scan" data-id="${escapeHtml(domain.id)}" ${domain.runningScan ? "disabled" : ""}>Scan e abrir relatorio</button>
        <button type="button" class="danger" data-action="delete" data-id="${escapeHtml(domain.id)}">Remover</button>
      </div>
      ${children.length ? `<div class="subdomain-list">${children.map(renderSubdomainRow).join("")}</div>` : ""}
    </article>
  `;
}

function renderSubdomainRow(domain) {
  const last = domain.lastStatus;
  const scan = domain.lastScanSummary;
  const statusClass = !last ? "pending" : last.ok ? "ok" : "down";
  const statusText = !last ? "Aguardando" : last.ok ? `HTTP ${last.status}` : `Falha${last.status ? ` ${last.status}` : ""}`;
  const scanText = domain.runningScan
    ? "Scan em execucao"
    : scan
      ? `Ultimo scan: ${scan.summary.findings} achados em ${scan.summary.pagesScanned} URLs`
      : "Aguardando scan";
  return `
    <div class="subdomain-row">
      <div>
        <strong>${escapeHtml(domain.label || domain.target)}</strong>
        <span>${escapeHtml(domain.target)}</span>
        <span>${escapeHtml(scanText)}</span>
      </div>
      <span class="status-dot ${statusClass}">${escapeHtml(statusText)}</span>
      <button type="button" data-action="check" data-id="${escapeHtml(domain.id)}" ${domain.runningStatus ? "disabled" : ""}>Checar</button>
      <button type="button" data-action="scan" data-id="${escapeHtml(domain.id)}" ${domain.runningScan ? "disabled" : ""}>Scan</button>
    </div>
  `;
}

function renderReport(report) {
  metrics.pages.textContent = report.summary.pagesScanned;
  metrics.high.textContent = report.summary.high;
  metrics.medium.textContent = report.summary.medium;
  metrics.low.textContent = report.summary.low;
  metrics.subdomains.textContent = report.summary.subdomainsFound || 0;
  targetLabel.textContent = `${report.target} - finalizado em ${formatDate(report.finishedAt)}`;
  summary.className = "summary";
  summary.innerHTML = `
    <strong>${report.summary.findings} achados em ${report.summary.pagesScanned} URLs.</strong>
    Subdominios encontrados: ${report.summary.subdomainsFound || 0}.
    Subdominios testados: ${report.summary.subdomainsTested || 0}.
    WAF: ${report.summary.wafDetected ? "sinais encontrados" : "nao identificado"}.
    HTTPS: ${report.summary.httpsAvailable ? "disponivel" : "nao validado"}.
  `;
  renderFindings(report);
  renderPages(report);
  renderWaf(report);
}

function renderAppReport(report) {
  appTargetLabel.textContent = `${report.target} - finalizado em ${formatDate(report.finishedAt)}`;
  appSummary.className = "summary";
  appSummary.innerHTML = `
    <strong>${report.summary.findings} achados em ${report.summary.pagesScanned} URLs avaliadas.</strong>
    Perfil: ${escapeHtml(report.options.appProfile || "generico")}.
    WAF: ${report.summary.wafDetected ? "sinais encontrados" : "nao identificado"}.
    HTTPS: ${report.summary.httpsAvailable ? "disponivel" : "nao validado"}.
  `;
  if (!report.findings.length) {
    appFindings.innerHTML = `<div class="summary empty">Nenhum achado registrado.</div>`;
    return;
  }
  appFindings.innerHTML = groupFindingsByUrl(report.findings)
    .map((group) => `
      <article class="finding-group">
        <header>
          <div>
            <h3>${escapeHtml(group.url)}</h3>
            <p>${group.items.length} evidencia${group.items.length === 1 ? "" : "s"} agrupada${group.items.length === 1 ? "" : "s"}</p>
          </div>
          <div class="severity-stack">${renderSeverityBadges(group.items)}</div>
        </header>
        <div class="finding-list">
          ${group.items.map((item) => `
            <section class="finding">
              <header>
                <h4>${escapeHtml(item.title)}</h4>
                <span class="badge ${item.severity}">${labelSeverity(item.severity)}</span>
              </header>
              <p><strong>Evidencia:</strong> ${escapeHtml(item.evidence)}</p>
              <p><strong>Recomendacao:</strong> ${escapeHtml(item.recommendation)}</p>
            </section>
          `).join("")}
        </div>
      </article>
    `)
    .join("");
}

function renderFindings(report) {
  if (!report.findings.length) {
    panels.findings.innerHTML = `<div class="summary empty">Nenhum achado registrado.</div>`;
    return;
  }
  panels.findings.innerHTML = groupFindingsByUrl(report.findings)
    .map((group) => `
      <article class="finding-group">
        <header>
          <div>
            <h3>${escapeHtml(group.url)}</h3>
            <p>${group.items.length} evidencia${group.items.length === 1 ? "" : "s"} agrupada${group.items.length === 1 ? "" : "s"}</p>
          </div>
          <div class="severity-stack">${renderSeverityBadges(group.items)}</div>
        </header>
        <div class="finding-list">
          ${group.items.map((item) => `
            <section class="finding">
              <header>
                <h4>${escapeHtml(item.title)}</h4>
                <span class="badge ${item.severity}">${labelSeverity(item.severity)}</span>
              </header>
              <p><strong>Evidencia:</strong> ${escapeHtml(item.evidence)}</p>
              <p><strong>Recomendacao:</strong> ${escapeHtml(item.recommendation)}</p>
            </section>
          `).join("")}
        </div>
      </article>
    `)
    .join("");
}

function renderPages(report) {
  if (!report.pages.length) {
    panels.pages.innerHTML = `<div class="summary empty">Nenhuma URL foi escaneada.</div>`;
    return;
  }
  panels.pages.innerHTML = report.pages
    .map((page) => `
      <article class="page-row">
        <header>
          <h3>${escapeHtml(page.title || page.url)}</h3>
          <span class="badge ${page.status && page.status < 400 ? "info" : "medium"}">HTTP ${page.status || "erro"}</span>
        </header>
        <p>${escapeHtml(page.url)}</p>
        <dl class="kv">
          <dt>URL final</dt><dd>${escapeHtml(page.finalUrl || "-")}</dd>
          <dt>Tempo</dt><dd>${page.responseTimeMs || "-"} ms</dd>
          <dt>Tecnologias</dt><dd>${escapeHtml(page.technologies.join(", ") || "Nao identificadas")}</dd>
          <dt>Cookies</dt><dd>${page.cookies.length}</dd>
          <dt>Links encontrados</dt><dd>${page.links.length}</dd>
          ${page.error ? `<dt>Erro</dt><dd>${escapeHtml(page.error)}</dd>` : ""}
        </dl>
      </article>
    `)
    .join("");
}

function renderWaf(report) {
  const tls = report.tls || {};
  const redirect = report.httpsRedirect || {};
  const dns = report.dnsRecords || {};
  panels.waf.innerHTML = `
    <article class="detail-box">
      <h3>WAF/CDN de seguranca</h3>
      <dl class="kv">
        <dt>Status</dt><dd>${report.waf.detected ? "Detectado" : "Nao identificado"}</dd>
        <dt>Fornecedores</dt><dd>${escapeHtml(report.waf.vendors.join(", ") || "-")}</dd>
        <dt>Evidencias</dt><dd>${escapeHtml(report.waf.evidence.join(" | ") || "-")}</dd>
      </dl>
    </article>
    <article class="detail-box">
      <h3>TLS e HTTPS</h3>
      <dl class="kv">
        <dt>TLS</dt><dd>${tls.ok ? "Conectado" : "Falhou"}</dd>
        <dt>Certificado confiavel</dt><dd>${tls.authorized ? "Sim" : "Nao"}</dd>
        <dt>Protocolo</dt><dd>${escapeHtml(tls.protocol || "-")}</dd>
        <dt>Cifra</dt><dd>${escapeHtml(tls.cipher || "-")}</dd>
        <dt>Validade</dt><dd>${escapeHtml([tls.validFrom, tls.validTo].filter(Boolean).join(" ate ") || "-")}</dd>
        <dt>Redirect HTTP</dt><dd>${redirect.ok ? "Redireciona para HTTPS" : "Nao confirmado"}</dd>
      </dl>
    </article>
    <article class="detail-box">
      <h3>DNS publico do dominio</h3>
      <dl class="kv">
        <dt>Dominio raiz</dt><dd>${escapeHtml(dns.domain || "-")}</dd>
        <dt>NS</dt><dd>${escapeHtml((dns.ns || []).join(", ") || "-")}</dd>
        <dt>MX</dt><dd>${escapeHtml((dns.mx || []).map((item) => `${item.exchange} (${item.priority})`).join(", ") || "-")}</dd>
        <dt>TXT</dt><dd>${escapeHtml((dns.txt || []).join(" | ") || "-")}</dd>
        <dt>SOA</dt><dd>${escapeHtml(dns.soa ? `${dns.soa.nsname} / ${dns.soa.hostmaster}` : "-")}</dd>
        <dt>CAA</dt><dd>${escapeHtml((dns.caa || []).map(formatDnsObject).join(", ") || "-")}</dd>
      </dl>
    </article>
    <article class="detail-box">
      <h3>Subdominios descobertos</h3>
      ${
        report.subdomains && report.subdomains.length
          ? report.subdomains.map((item) => `<p><strong>${escapeHtml(item.host)}:</strong> ${escapeHtml(item.addresses.length ? item.addresses.join(", ") : item.dnsStatus || "sem A/AAAA confirmado")}<br><span class="muted-line">Fontes: ${escapeHtml((item.sources || []).join(", ") || "-")} | Resolvedores: ${escapeHtml((item.resolvers || []).join(", ") || "-")}</span></p>`).join("")
          : "<p>Nenhum subdominio publico foi confirmado por DNS neste scan.</p>"
      }
      <dl class="kv">
        <dt>Fontes</dt><dd>${escapeHtml((report.discovery?.sources || []).map((source) => `${source.name}: ${source.count}`).join(" | ") || "-")}</dd>
        <dt>Observacao</dt><dd>${escapeHtml(report.discovery?.note || "-")}</dd>
      </dl>
    </article>
    <article class="detail-box">
      <h3>Probes ativos</h3>
      ${
        report.waf.probes.length
          ? report.waf.probes.map((probe) => `<p><strong>${escapeHtml(probe.name)}:</strong> ${escapeHtml(probe.evidence)}</p>`).join("")
          : "<p>Nao executados neste scan.</p>"
      }
    </article>
  `;
}

function findingsToCsv(report) {
  const rows = [["Severidade", "Titulo", "URL", "Evidencia", "Recomendacao"]];
  for (const group of groupFindingsByUrl(report.findings)) {
    for (const item of group.items) {
    rows.push([labelSeverity(item.severity), item.title, item.url, item.evidence, item.recommendation]);
    }
  }
  return rows.map((row) => row.map(csvCell).join(",")).join("\n");
}

function reportToHtml(report) {
  const findings = groupFindingsByUrl(report.findings).map((group) => `
    <h2>${escapeHtml(group.url)}</h2>
    <table>
      <thead><tr><th>Severidade</th><th>Titulo</th><th>Evidencia</th><th>Recomendacao</th></tr></thead>
      <tbody>
        ${group.items.map((item) => `
          <tr>
            <td>${escapeHtml(labelSeverity(item.severity))}</td>
            <td>${escapeHtml(item.title)}</td>
            <td>${escapeHtml(item.evidence)}</td>
            <td>${escapeHtml(item.recommendation)}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `).join("");
  return `<!doctype html>
<html lang="pt-BR">
<meta charset="utf-8">
<title>Relatorio SCAN Dominio</title>
<style>
body{font-family:Arial,sans-serif;margin:32px;color:#18202f}h1{margin-bottom:4px}h2{margin-top:28px;font-size:18px;overflow-wrap:anywhere}table{border-collapse:collapse;width:100%;margin-top:10px}th,td{border:1px solid #dce2ea;padding:8px;text-align:left;vertical-align:top}th{background:#f5f7fa}.meta{color:#677084}
</style>
<h1>Relatorio SCAN Dominio</h1>
<p class="meta">${escapeHtml(report.target)} - ${escapeHtml(formatDate(report.finishedAt))}</p>
<p>${report.summary.findings} achados em ${report.summary.pagesScanned} URLs. Subdominios encontrados: ${report.summary.subdomainsFound || 0}. Subdominios testados: ${report.summary.subdomainsTested || 0}. WAF: ${report.summary.wafDetected ? "detectado" : "nao identificado"}.</p>
${findings}
</html>`;
}

function download(filename, type, content) {
  if (!currentReport) return;
  downloadReport(currentReport, filename, type, content);
}

function downloadReport(report, filename, type, content) {
  if (!report) return;
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function csvCell(value) {
  return `"${String(value ?? "").replaceAll('"', '""')}"`;
}

function groupFindingsByUrl(findings) {
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  const groups = new Map();
  for (const item of findings) {
    const url = item.url || "Sem URL";
    if (!groups.has(url)) groups.set(url, []);
    groups.get(url).push(item);
  }
  return [...groups.entries()].map(([url, items]) => ({
    url,
    items: items.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9))
  }));
}

function renderSeverityBadges(items) {
  const counts = items.reduce((total, item) => {
    total[item.severity] = (total[item.severity] || 0) + 1;
    return total;
  }, {});
  return ["high", "medium", "low", "info"]
    .filter((severity) => counts[severity])
    .map((severity) => `<span class="badge ${severity}">${labelSeverity(severity)} ${counts[severity]}</span>`)
    .join("");
}

function formatDnsObject(value) {
  if (!value || typeof value !== "object") return String(value ?? "");
  return Object.entries(value).map(([key, item]) => `${key}=${item}`).join(" ");
}

function labelSeverity(value) {
  return {
    high: "Alto",
    medium: "Medio",
    low: "Baixo",
    info: "Info"
  }[value] || value;
}

function formatEmailConfig(domain, recipients, delivery) {
  if (!domain.weeklyEmailEnabled) return "Desativado";
  if (!recipients.length) return "Sem destinatarios cadastrados";
  const deliveryText = delivery
    ? ` Ultimo envio: ${delivery.status === "sent" ? "enviado" : "falhou"} em ${formatDate(delivery.finishedAt || delivery.at)}${delivery.error ? ` - ${delivery.error}` : ""}.`
    : " Aguardando primeiro envio automatico.";
  return `${recipients.join(", ")}.${deliveryText}`;
}

function formatDate(value) {
  if (!value) return "-";
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "short",
    timeStyle: "medium"
  }).format(new Date(value));
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
