import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import tls from "node:tls";
import net from "node:net";
import dns from "node:dns/promises";
import { setMaxListeners } from "node:events";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, "public");
const dataDir = path.join(__dirname, "data");
const storePath = path.join(dataDir, "domains.json");

await loadEnvFile(path.join(__dirname, ".env"));

const PORT = Number(process.env.PORT || 4173);
const MAX_BODY_BYTES = 650_000;
const USER_AGENT = "SCAN-Dominio/1.0 (+authorized-security-check)";
const MAX_CT_NAMES = 1500;
const MAX_DISCOVERY_NAMES = 3000;
const MONITOR_INTERVAL_MS = 60 * 60 * 1000;
const WEEKLY_SCAN_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000;
const SCHEDULER_TICK_MS = 60 * 1000;
const HISTORY_LIMIT = 168;
const REPORT_LIMIT = 8;
const SUBDOMAIN_SCAN_LIMIT = Number(process.env.SUBDOMAIN_SCAN_LIMIT || 80);
const execFileAsync = promisify(execFile);
const DNS_PUBLIC_RESOLVERS = [
  "system",
  "https://dns.google/resolve",
  "https://cloudflare-dns.com/dns-query"
];
const COMMON_SUBDOMAINS = [
  "www",
  "app",
  "api",
  "admin",
  "portal",
  "login",
  "sso",
  "auth",
  "mail",
  "webmail",
  "smtp",
  "vpn",
  "remote",
  "intranet",
  "extranet",
  "dev",
  "test",
  "stage",
  "staging",
  "homolog",
  "hml",
  "qa",
  "preprod",
  "prod",
  "cdn",
  "assets",
  "static",
  "files",
  "docs",
  "help",
  "support",
  "blog",
  "shop",
  "store",
  "status",
  "monitor",
  "grafana",
  "kibana",
  "jenkins",
  "git",
  "gitlab",
  "jira",
  "confluence",
  "sharepoint",
  "moodle",
  "ead",
  "alunos",
  "academico",
  "biblioteca",
  "financeiro",
  "rh",
  "ti",
  "ouvidoria",
  "transparencia",
  "sistemas",
  "sistema",
  "servicos",
  "apps",
  "api-dev",
  "api-hml",
  "api-staging",
  "gateway",
  "ws",
  "webservice",
  "webservices",
  "ftp",
  "sftp",
  "ns1",
  "ns2",
  "mx",
  "owa",
  "autodiscover",
  "msoid",
  "lyncdiscover",
  "sip",
  "zabbix",
  "prometheus",
  "sonar",
  "nexus",
  "registry",
  "docker",
  "adminer",
  "phpmyadmin",
  "db",
  "mysql",
  "postgres",
  "elastic",
  "opensearch",
  "logs",
  "backup",
  "bk",
  "old",
  "novo",
  "beta",
  "demo",
  "treinamento",
  "pesquisa",
  "eventos",
  "noticias",
  "site",
  "web"
];

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml"
};

let store = await loadStore();
const manualScanJobs = new Map();
let saveChain = Promise.resolve();

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", `http://${req.headers.host}`);
    if (url.pathname === "/api/domains" && req.method === "GET") {
      return sendJson(res, 200, publicStore());
    }

    if (url.pathname === "/api/domains" && req.method === "POST") {
      const payload = await readJson(req);
      const domain = await addDomain(payload);
      return sendJson(res, 201, { domain, store: publicStore() });
    }

    const domainMatch = url.pathname.match(/^\/api\/domains\/([^/]+)(?:\/([^/]+))?$/);
    if (domainMatch) {
      const [, domainId, action] = domainMatch;
      if (req.method === "DELETE" && !action) {
        await removeDomain(domainId);
        return sendJson(res, 200, publicStore());
      }
      if (req.method === "POST" && action === "check") {
        const domain = getDomain(domainId);
        await runDomainStatusCheck(domain, { manual: true });
        return sendJson(res, 200, { domain, store: publicStore() });
      }
      if (req.method === "POST" && action === "scan") {
        const domain = getDomain(domainId);
        await runDomainSecurityScan(domain, { manual: true });
        return sendJson(res, 200, { domain, store: publicStore() });
      }
    }

    if (url.pathname === "/api/manual-scans" && req.method === "POST") {
      const payload = await readJson(req);
      const job = createManualScanJob(payload);
      return sendJson(res, 202, serializeManualScanJob(job));
    }

    const manualScanMatch = url.pathname.match(/^\/api\/manual-scans\/([^/]+)$/);
    if (manualScanMatch) {
      const job = manualScanJobs.get(manualScanMatch[1]);
      if (!job) return sendJson(res, 404, { error: "Scan nao encontrado." });
      if (req.method === "GET") {
        return sendJson(res, 200, serializeManualScanJob(job));
      }
      if (req.method === "DELETE") {
        cancelManualScanJob(job);
        return sendJson(res, 200, serializeManualScanJob(job));
      }
    }

    if (req.method === "POST" && url.pathname === "/api/scan") {
      const payload = await readJson(req);
      const report = await runScan(payload);
      return sendJson(res, 200, report);
    }

    if (req.method !== "GET") {
      return sendJson(res, 405, { error: "Metodo nao permitido." });
    }

    await serveStatic(url.pathname, res);
  } catch (error) {
    const status = error.statusCode || 500;
    console.error(`[${new Date().toISOString()}] ${req.method} ${req.url} falhou:`, error);
    sendJson(res, status, {
      error: error.publicMessage || "Falha ao executar a operacao.",
      detail: process.env.NODE_ENV === "development" ? String(error.stack || error) : undefined
    });
  }
});

server.listen(PORT, () => {
  console.log(`Ferramenta SCAN Dominio pronta em http://localhost:${PORT}`);
});

startScheduler();

async function serveStatic(pathname, res) {
  const safePath = pathname === "/" ? "/index.html" : decodeURIComponent(pathname);
  const requested = path.normalize(path.join(publicDir, safePath));
  if (!requested.startsWith(publicDir)) {
    return sendJson(res, 403, { error: "Caminho invalido." });
  }

  try {
    const body = await fs.readFile(requested);
    const ext = path.extname(requested);
    res.writeHead(200, {
      "content-type": mimeTypes[ext] || "application/octet-stream",
      "cache-control": "no-store"
    });
    res.end(body);
  } catch {
    sendJson(res, 404, { error: "Arquivo nao encontrado." });
  }
}

async function readJson(req) {
  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 40_000) {
      throw httpError(413, "Requisicao muito grande.");
    }
  }
  try {
    return JSON.parse(body || "{}");
  } catch {
    throw httpError(400, "JSON invalido.");
  }
}

async function loadStore() {
  try {
    await fs.mkdir(dataDir, { recursive: true });
    const raw = await fs.readFile(storePath, "utf8");
    const data = JSON.parse(raw);
    return {
      domains: Array.isArray(data.domains) ? data.domains.map(normalizeStoredDomain) : []
    };
  } catch {
    return { domains: [] };
  }
}

async function saveStore() {
  const write = saveChain.catch(() => {}).then(async () => {
    await fs.mkdir(dataDir, { recursive: true });
    const tempPath = `${storePath}.${process.pid}.${Date.now()}.tmp`;
    await fs.writeFile(tempPath, JSON.stringify(persistableStore(), null, 2));
    await fs.rename(tempPath, storePath);
  });
  saveChain = write;
  return write;
}

function publicStore() {
  return {
    now: new Date().toISOString(),
    monitorIntervalMs: MONITOR_INTERVAL_MS,
    weeklyScanIntervalMs: WEEKLY_SCAN_INTERVAL_MS,
    domains: store.domains.map((domain) => ({
      ...domain,
      runningStatus: Boolean(domain.runningStatus),
      runningScan: Boolean(domain.runningScan)
    }))
  };
}

function persistableStore() {
  return {
    domains: store.domains.map(({ runningStatus, runningScan, ...domain }) => ({
      ...domain,
      history: Array.isArray(domain.history) ? domain.history.slice(-HISTORY_LIMIT) : [],
      reports: Array.isArray(domain.reports) ? domain.reports.slice(-REPORT_LIMIT) : [],
      errors: Array.isArray(domain.errors) ? domain.errors.slice(-20) : [],
      emailDeliveries: Array.isArray(domain.emailDeliveries) ? domain.emailDeliveries.slice(-20) : []
    }))
  };
}

async function addDomain(payload) {
  const targetUrl = normalizeTarget(payload.target);
  const now = new Date();
  const rootDomain = getRootDomain(targetUrl.hostname.toLowerCase());
  const baseOptions = {
    enabled: payload.enabled !== false,
    followPaths: Boolean(payload.followPaths),
    activeWafProbe: Boolean(payload.activeWafProbe),
    emailRecipients: parseEmailRecipients(payload.emailRecipients),
    weeklyEmailEnabled: payload.weeklyEmailEnabled !== false,
    maxPages: clamp(Number(payload.maxPages || 100), 1, 500),
    timeoutMs: clamp(Number(payload.timeoutMs || 9000), 2500, 20000)
  };
  const familyId = crypto.randomUUID();
  const domain = upsertMonitoredDomain({
    id: crypto.randomUUID(),
    label: cleanText(payload.label || targetUrl.hostname),
    target: targetUrl.origin,
    rootDomain,
    familyId,
    parentId: null,
    kind: "root",
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
    includeSubdomains: payload.includeSubdomains !== false,
    ...baseOptions,
    nextStatusAt: new Date(Date.now() + MONITOR_INTERVAL_MS).toISOString(),
    nextScanAt: new Date(Date.now() + WEEKLY_SCAN_INTERVAL_MS).toISOString(),
    history: [],
    reports: []
  });

  await saveStore();
  queueDomainSecurityScan(domain, { manual: false, sendEmail: false });
  return domain;
}

async function removeDomain(domainId) {
  const before = store.domains.length;
  const domain = store.domains.find((item) => item.id === domainId);
  store.domains = store.domains.filter((item) => item.id !== domainId && item.parentId !== domainId);
  if (store.domains.length === before) throw httpError(404, "Dominio nao encontrado.");
  if (domain?.kind === "root") {
    store.domains = store.domains.filter((item) => item.familyId !== domain.familyId || item.id === domain.id);
    store.domains = store.domains.filter((item) => item.id !== domain.id);
  }
  await saveStore();
}

function getDomain(domainId) {
  const domain = store.domains.find((item) => item.id === domainId);
  if (!domain) throw httpError(404, "Dominio nao encontrado.");
  return domain;
}

function normalizeStoredDomain(domain) {
  const now = new Date().toISOString();
  return {
    id: domain.id || crypto.randomUUID(),
    label: domain.label || domain.target || "Dominio",
    target: domain.target,
    rootDomain: domain.rootDomain || getRootDomain(new URL(domain.target).hostname.toLowerCase()),
    familyId: domain.familyId || domain.id || crypto.randomUUID(),
    parentId: domain.parentId || null,
    kind: domain.kind || "root",
    createdAt: domain.createdAt || now,
    updatedAt: domain.updatedAt || now,
    enabled: domain.enabled !== false,
    includeSubdomains: domain.includeSubdomains !== false,
    followPaths: Boolean(domain.followPaths),
    activeWafProbe: Boolean(domain.activeWafProbe),
    maxPages: clamp(Number(domain.maxPages || 100), 1, 500),
    timeoutMs: clamp(Number(domain.timeoutMs || 9000), 2500, 20000),
    nextStatusAt: domain.nextStatusAt || now,
    nextScanAt: domain.nextScanAt || now,
    lastStatus: domain.lastStatus || null,
    lastScanSummary: domain.lastScanSummary || null,
    history: Array.isArray(domain.history) ? domain.history.slice(-HISTORY_LIMIT) : [],
    reports: Array.isArray(domain.reports) ? domain.reports.slice(-REPORT_LIMIT) : [],
    errors: Array.isArray(domain.errors) ? domain.errors.slice(-20) : [],
    emailRecipients: parseEmailRecipients(domain.emailRecipients),
    weeklyEmailEnabled: domain.weeklyEmailEnabled !== false,
    emailDeliveries: Array.isArray(domain.emailDeliveries) ? domain.emailDeliveries.slice(-20) : [],
    discoverySources: Array.isArray(domain.discoverySources) ? domain.discoverySources : [],
    dnsAddresses: Array.isArray(domain.dnsAddresses) ? domain.dnsAddresses : [],
    runningStatus: false,
    runningScan: false
  };
}

function upsertMonitoredDomain(nextDomain) {
  const normalized = normalizeStoredDomain(nextDomain);
  const existing = store.domains.find((domain) => domain.target.toLowerCase() === normalized.target.toLowerCase());
  if (!existing) {
    store.domains.push(normalized);
    return normalized;
  }

  const preserved = {
    id: existing.id,
    createdAt: existing.createdAt,
    history: existing.history || [],
    reports: existing.reports || [],
    errors: existing.errors || [],
    emailDeliveries: existing.emailDeliveries || [],
    lastStatus: existing.lastStatus || null,
    lastScanSummary: existing.lastScanSummary || null
  };
  Object.assign(existing, normalized, preserved, {
    updatedAt: new Date().toISOString(),
    runningStatus: false,
    runningScan: false
  });
  return existing;
}

function attachReport(domain, report) {
  const summary = {
    target: report.target,
    startedAt: report.startedAt,
    finishedAt: report.finishedAt,
    summary: report.summary
  };
  domain.lastScanSummary = summary;
  domain.reports = domain.reports || [];
  domain.reports.push({ id: crypto.randomUUID(), createdAt: report.finishedAt, report });
  domain.reports = domain.reports.slice(-REPORT_LIMIT);
}

async function sendWeeklyReportEmail(domain, report) {
  const recipients = parseEmailRecipients(domain.emailRecipients);
  if (!recipients.length) return;

  const delivery = {
    id: crypto.randomUUID(),
    type: "weekly-report",
    at: new Date().toISOString(),
    recipients,
    status: "pending",
    error: null
  };
  domain.emailDeliveries = [...(domain.emailDeliveries || []), delivery].slice(-20);

  try {
    const subject = `[SCAN Dominio] Relatorio semanal - ${domain.label || domain.target}`;
    await sendSmtpMail({
      to: recipients,
      subject,
      html: reportToEmailHtml(domain, report),
      text: reportToEmailText(domain, report)
    });
    delivery.status = "sent";
  } catch (error) {
    delivery.status = "failed";
    delivery.error = String(error?.message || error);
  } finally {
    delivery.finishedAt = new Date().toISOString();
    await saveStore();
  }
}

function reportToEmailText(domain, report) {
  const lines = [
    `Relatorio semanal do monitoramento: ${domain.label || domain.target}`,
    `Alvo: ${report.target}`,
    `Finalizado em: ${formatDateTime(report.finishedAt)}`,
    "",
    `URLs testadas: ${report.summary.pagesScanned}`,
    `Achados: ${report.summary.findings}`,
    `Altos: ${report.summary.high}`,
    `Medios: ${report.summary.medium}`,
    `Baixos: ${report.summary.low}`,
    `Informativos: ${report.summary.info}`,
    `Subdominios encontrados: ${report.summary.subdomainsFound || 0}`,
    `Subdominios testados: ${report.summary.subdomainsTested || 0}`,
    `WAF: ${report.summary.wafDetected ? "detectado" : "nao identificado"}`,
    "",
    "Principais evidencias:"
  ];

  for (const group of groupFindingsByUrl(report.findings).slice(0, 12)) {
    lines.push("");
    lines.push(group.url);
    for (const item of group.findings.slice(0, 6)) {
      lines.push(`- [${item.severity}] ${item.title}: ${item.evidence}`);
    }
  }

  return lines.join("\n");
}

function reportToEmailHtml(domain, report) {
  const severityRows = [
    ["Alto", report.summary.high, "#ff6b5f"],
    ["Medio", report.summary.medium, "#f6a04d"],
    ["Baixo", report.summary.low, "#6aa7ff"],
    ["Info", report.summary.info, "#9aa3af"]
  ].map(([label, value, color]) => `
    <td style="padding:12px;border:1px solid #303238;border-radius:8px;background:#1d1d1f">
      <div style="font-size:12px;color:#a2a7b0;text-transform:uppercase">${label}</div>
      <div style="font-size:28px;font-weight:800;color:${color}">${value}</div>
    </td>
  `).join("");

  const findings = groupFindingsByUrl(report.findings).slice(0, 20).map((group) => `
    <h3 style="margin:22px 0 8px;font-size:16px;color:#ececf0;word-break:break-word">${escapeHtml(group.url)}</h3>
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse">
      ${group.findings.map((item) => `
        <tr>
          <td style="padding:10px;border:1px solid #303238;vertical-align:top;color:#ececf0">
            <strong>${escapeHtml(labelSeverity(item.severity))} - ${escapeHtml(item.title)}</strong>
            <div style="margin-top:6px;color:#a2a7b0">Evidencia: ${escapeHtml(item.evidence)}</div>
            <div style="margin-top:6px;color:#a2a7b0">Recomendacao: ${escapeHtml(item.recommendation)}</div>
          </td>
        </tr>
      `).join("")}
    </table>
  `).join("");

  return `<!doctype html>
<html lang="pt-BR">
  <body style="margin:0;background:#101112;color:#ececf0;font-family:Arial,sans-serif">
    <div style="max-width:860px;margin:0 auto;padding:28px">
      <p style="margin:0 0 6px;color:#a2a7b0;font-size:12px;text-transform:uppercase">Relatorio semanal</p>
      <h1 style="margin:0 0 8px;font-size:28px">${escapeHtml(domain.label || domain.target)}</h1>
      <p style="margin:0 0 22px;color:#a2a7b0">${escapeHtml(report.target)} - ${escapeHtml(formatDateTime(report.finishedAt))}</p>
      <table role="presentation" width="100%" cellspacing="8" cellpadding="0" style="margin:0 0 20px">${severityRows}</table>
      <p style="font-size:15px;line-height:1.5;color:#d9dbe1">
        ${report.summary.findings} achados em ${report.summary.pagesScanned} URLs.
        Subdominios encontrados: ${report.summary.subdomainsFound || 0}.
        Subdominios testados: ${report.summary.subdomainsTested || 0}.
        WAF: ${report.summary.wafDetected ? "sinais encontrados" : "nao identificado"}.
      </p>
      ${findings || `<div style="padding:14px;border:1px solid #303238;border-radius:8px;background:#1d1d1f;color:#a2a7b0">Nenhum achado registrado neste scan.</div>`}
    </div>
  </body>
</html>`;
}

function findPageForOrigin(report, origin) {
  return report.pages.find((page) => {
    try {
      return new URL(page.url).origin.toLowerCase() === origin.toLowerCase();
    } catch {
      return false;
    }
  });
}

function statusFromPage(page) {
  return {
    checkedAt: new Date().toISOString(),
    url: page.url,
    finalUrl: page.finalUrl,
    status: page.status,
    ok: Boolean(page.status && page.status >= 200 && page.status < 400),
    responseTimeMs: page.responseTimeMs,
    contentType: page.headers?.["content-type"] || "",
    server: page.headers?.server || "",
    error: page.error || null
  };
}

function syncDiscoveredSubdomains(parentDomain, report, baseOptions) {
  const now = new Date();
  for (const subdomain of report.subdomains.filter((item) => item.dnsStatus === "resolvido")) {
    const childUrl = new URL(`https://${subdomain.host}`);
    const page = findPageForOrigin(report, childUrl.origin);
    const existing = store.domains.find((domain) => domain.target.toLowerCase() === childUrl.origin.toLowerCase());
    const child = upsertMonitoredDomain({
      id: crypto.randomUUID(),
      label: subdomain.host,
      target: childUrl.origin,
      rootDomain: parentDomain.rootDomain,
      familyId: parentDomain.familyId,
      parentId: parentDomain.id,
      kind: "subdomain",
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      enabled: baseOptions.enabled !== false,
      includeSubdomains: false,
      followPaths: false,
      activeWafProbe: Boolean(baseOptions.activeWafProbe),
      emailRecipients: [],
      weeklyEmailEnabled: false,
      maxPages: baseOptions.maxPages,
      timeoutMs: baseOptions.timeoutMs,
      nextStatusAt: new Date(Date.now() + MONITOR_INTERVAL_MS).toISOString(),
      nextScanAt: existing?.lastScanSummary ? new Date(Date.now() + WEEKLY_SCAN_INTERVAL_MS).toISOString() : now.toISOString(),
      history: [],
      reports: []
    });
    child.parentId = parentDomain.id;
    child.familyId = parentDomain.familyId;
    child.kind = "subdomain";
    child.rootDomain = parentDomain.rootDomain;
    child.discoverySources = subdomain.sources || [];
    child.dnsAddresses = subdomain.addresses || [];
    child.updatedAt = now.toISOString();
    if (page) {
      child.lastStatus = statusFromPage(page);
      child.history = [...(child.history || []), child.lastStatus].slice(-HISTORY_LIMIT);
    }
  }
}

function startScheduler() {
  setInterval(() => {
    runDueJobs().catch((error) => console.error("Falha no agendador:", error));
  }, SCHEDULER_TICK_MS).unref();
  runDueJobs().catch((error) => console.error("Falha inicial no agendador:", error));
}

async function runDueJobs() {
  const now = Date.now();
  for (const domain of store.domains) {
    if (!domain.enabled) continue;
    if (!domain.runningStatus && Date.parse(domain.nextStatusAt) <= now) {
      queueDomainStatusCheck(domain, { manual: false });
    }
    if (!domain.runningScan && Date.parse(domain.nextScanAt) <= now) {
      queueDomainSecurityScan(domain, { manual: false });
    }
  }
}

function queueDomainStatusCheck(domain, options) {
  setTimeout(() => {
    runDomainStatusCheck(domain, options).catch((error) => safelyRecordDomainError(domain, "status", error));
  }, 0).unref();
}

function queueDomainSecurityScan(domain, options) {
  setTimeout(() => {
    runDomainSecurityScan(domain, options).catch((error) => safelyRecordDomainError(domain, "scan", error));
  }, 0).unref();
}

function queueDiscoveredSubdomainScans(parentDomain, { reason }) {
  const children = store.domains
    .filter((domain) => domain.enabled && domain.parentId === parentDomain.id && domain.kind === "subdomain")
    .filter((domain) => !domain.runningScan)
    .slice(0, SUBDOMAIN_SCAN_LIMIT);
  if (!children.length) return;

  setTimeout(async () => {
    for (const child of children) {
      if (!store.domains.some((domain) => domain.id === child.id)) continue;
      if (child.runningScan) continue;
      child.lastQueuedScanReason = reason;
      try {
        await runDomainSecurityScan(child, { manual: false, sendEmail: false });
      } catch (error) {
        await safelyRecordDomainError(child, "scan", error);
      }
    }
  }, 0).unref();
}

async function runDomainStatusCheck(domain, { manual }) {
  if (domain.runningStatus) return domain.lastStatus;
  domain.runningStatus = true;
  try {
    const status = await checkUrlStatus(domain.target, domain.timeoutMs);
    domain.lastStatus = status;
    domain.history.push(status);
    domain.history = domain.history.slice(-HISTORY_LIMIT);
    domain.nextStatusAt = new Date(Date.now() + MONITOR_INTERVAL_MS).toISOString();
    if (manual) domain.lastManualStatusAt = status.checkedAt;
    await saveStore();
    return status;
  } finally {
    domain.runningStatus = false;
  }
}

async function runDomainSecurityScan(domain, { manual, sendEmail = !manual }) {
  if (domain.runningScan) return domain.lastScanSummary;
  domain.runningScan = true;
  try {
    let shouldQueueSubdomainScans = false;
    const report = await runScan({
      target: domain.target,
      maxPages: domain.maxPages,
      timeoutMs: domain.timeoutMs,
      includeSubdomains: domain.includeSubdomains,
      followPaths: domain.followPaths,
      activeWafProbe: domain.activeWafProbe
    });
    attachReport(domain, report);
    if (domain.kind === "root" && domain.includeSubdomains) {
      syncDiscoveredSubdomains(domain, report, {
        enabled: domain.enabled,
        followPaths: domain.followPaths,
        activeWafProbe: domain.activeWafProbe,
        maxPages: domain.maxPages,
        timeoutMs: domain.timeoutMs
      });
      shouldQueueSubdomainScans = true;
    }
    domain.nextScanAt = new Date(Date.now() + WEEKLY_SCAN_INTERVAL_MS).toISOString();
    if (manual) domain.lastManualScanAt = report.finishedAt;
    await saveStore();
    if (shouldQueueSubdomainScans) {
      queueDiscoveredSubdomainScans(domain, { reason: manual ? "manual-root-scan" : "root-scan" });
    }
    if (sendEmail && domain.weeklyEmailEnabled && domain.emailRecipients?.length) {
      await sendWeeklyReportEmail(domain, report);
    }
    return domain.lastScanSummary;
  } finally {
    domain.runningScan = false;
  }
}

async function recordDomainError(domain, type, error) {
  domain.errors = domain.errors || [];
  domain.errors.push({
    type,
    at: new Date().toISOString(),
    message: String(error?.message || error)
  });
  domain.errors = domain.errors.slice(-20);
  domain.runningStatus = false;
  domain.runningScan = false;
  await saveStore();
}

async function safelyRecordDomainError(domain, type, error) {
  try {
    await recordDomainError(domain, type, error);
  } catch (recordError) {
    console.error(`[${new Date().toISOString()}] Falha ao registrar erro de ${type} para ${domain?.target}:`, recordError);
  }
}

async function checkUrlStatus(target, timeoutMs) {
  const url = normalizeTarget(target);
  const started = Date.now();
  const checkedAt = new Date().toISOString();
  try {
    let response = await fetchWithTimeout(url.href, timeoutMs, { method: "HEAD", redirect: "follow" });
    if ([405, 501].includes(response.status)) {
      response = await fetchWithTimeout(url.href, timeoutMs, { method: "GET", redirect: "follow" });
    }
    const responseTimeMs = Date.now() - started;
    return {
      checkedAt,
      url: url.href,
      finalUrl: response.url,
      status: response.status,
      ok: response.status >= 200 && response.status < 400,
      responseTimeMs,
      contentType: response.headers.get("content-type") || "",
      server: response.headers.get("server") || "",
      error: null
    };
  } catch (error) {
    return {
      checkedAt,
      url: url.href,
      finalUrl: url.href,
      status: null,
      ok: false,
      responseTimeMs: Date.now() - started,
      contentType: "",
      server: "",
      error: String(error.message || error)
    };
  }
}

function createManualScanJob(payload) {
  const controller = new AbortController();
  const job = {
    id: crypto.randomUUID(),
    status: "running",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    payload,
    report: null,
    error: null,
    controller
  };
  manualScanJobs.set(job.id, job);
  runScan(payload, { signal: controller.signal })
    .then((report) => {
      job.status = "completed";
      job.report = report;
      job.updatedAt = new Date().toISOString();
    })
    .catch((error) => {
      job.status = controller.signal.aborted ? "cancelled" : "failed";
      job.error = controller.signal.aborted ? "Scan cancelado pelo usuario." : String(error.message || error);
      job.updatedAt = new Date().toISOString();
    });
  return job;
}

function cancelManualScanJob(job) {
  if (job.status !== "running") return;
  job.status = "cancelling";
  job.updatedAt = new Date().toISOString();
  job.controller.abort();
}

function serializeManualScanJob(job) {
  return {
    id: job.id,
    status: job.status,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    payload: job.payload,
    report: job.report,
    error: job.error
  };
}

function throwIfAborted(signal) {
  if (signal?.aborted) {
    const error = new Error("Scan cancelado pelo usuario.");
    error.name = "AbortError";
    throw error;
  }
}

async function runScan(payload, context = {}) {
  const { signal } = context;
  if (signal) setMaxListeners(0, signal);
  throwIfAborted(signal);
  const targetUrl = normalizeTarget(payload.target);
  const maxPages = clamp(Number(payload.maxPages || 100), 1, 500);
  const timeoutMs = clamp(Number(payload.timeoutMs || 9000), 2500, 20000);
  const includeSubdomains = Boolean(payload.includeSubdomains);
  const followPaths = Boolean(payload.followPaths);
  const activeWafProbe = Boolean(payload.activeWafProbe);
  const appProfile = payload.appProfile || null;
  const baseHost = targetUrl.hostname.toLowerCase();
  const rootDomain = getRootDomain(baseHost);
  const startedAt = new Date();
  const report = {
    target: targetUrl.origin,
    startedAt: startedAt.toISOString(),
    finishedAt: null,
    options: { maxPages, timeoutMs, includeSubdomains, followPaths, activeWafProbe, appProfile },
    summary: {
      pagesScanned: 0,
      findings: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      wafDetected: false,
      httpsAvailable: targetUrl.protocol === "https:",
      subdomainsFound: 0,
      subdomainsTested: 0
    },
    tls: null,
    httpsRedirect: null,
    dnsRecords: null,
    discovery: {
      mode: includeSubdomains ? "certificate-transparency-and-public-dns" : "disabled",
      sources: [],
      resolvers: DNS_PUBLIC_RESOLVERS,
      note: "A descoberta lista nomes expostos em fontes publicas. DNS privado ou nomes nunca publicados podem nao aparecer."
    },
    waf: { detected: false, vendors: [], evidence: [], probes: [] },
    subdomains: [],
    pages: [],
    findings: [],
    findingsByUrl: [],
    errors: []
  };

  report.tls = await inspectTls(baseHost, timeoutMs);
  throwIfAborted(signal);
  report.httpsRedirect = await inspectHttpsRedirect(baseHost, timeoutMs, signal);
  throwIfAborted(signal);
  report.dnsRecords = await inspectPublicDns(rootDomain, timeoutMs);

  const discovery = includeSubdomains ? await discoverSubdomains(rootDomain, baseHost, timeoutMs, signal) : { subdomains: [], sources: [] };
  const discoveredSubdomains = discovery.subdomains;
  report.subdomains = discoveredSubdomains;
  report.discovery.sources = discovery.sources;
  report.summary.subdomainsFound = discoveredSubdomains.length;

  const queue = [targetUrl.href];
  for (const subdomain of discoveredSubdomains) {
    if (queue.length >= maxPages) break;
    if (subdomain.dnsStatus !== "resolvido") continue;
    queue.push(`https://${subdomain.host}/`);
  }
  const seen = new Set();
  const scannedOrigins = new Set();

  while (queue.length && report.pages.length < maxPages) {
    throwIfAborted(signal);
    const currentHref = queue.shift();
    if (!currentHref || seen.has(currentHref)) continue;
    seen.add(currentHref);

    let currentUrl;
    try {
      currentUrl = new URL(currentHref);
    } catch {
      continue;
    }
    if (!isAllowedHost(currentUrl.hostname, baseHost, rootDomain, includeSubdomains)) continue;

    const page = await inspectPage(currentUrl, timeoutMs, signal, appProfile);
    addPageToReport(report, page, scannedOrigins);

    if (page.error && currentUrl.protocol === "https:" && report.pages.length < maxPages) {
      const fallbackUrl = new URL(currentUrl.href);
      fallbackUrl.protocol = "http:";
      fallbackUrl.port = "";
      const fallbackHref = fallbackUrl.href;
      if (!seen.has(fallbackHref)) {
        seen.add(fallbackHref);
        const fallbackPage = await inspectPage(fallbackUrl, timeoutMs, signal, appProfile);
        addPageToReport(report, fallbackPage, scannedOrigins);
      }
    }

    if (followPaths && page.links.length) {
      for (const link of page.links) {
        if (!seen.has(link) && queue.length + report.pages.length < maxPages * 4) {
          queue.push(link);
        }
      }
    }
  }

  if (activeWafProbe) {
    const probeTargets = [...scannedOrigins].map((origin) => new URL(origin));
    report.waf.probes = [];
    for (const probeTarget of probeTargets) {
      throwIfAborted(signal);
      report.waf.probes.push(...await runWafProbes(probeTarget, timeoutMs, signal));
    }
    for (const probe of report.waf.probes) {
      if (probe.suspicious) {
        report.waf.detected = true;
        report.waf.evidence.push(probe.evidence);
      }
    }
  }

  addGlobalFindings(report);
  report.findingsByUrl = groupFindingsByUrl(report.findings);
  report.summary.pagesScanned = report.pages.length;
  report.summary.findings = report.findings.length;
  for (const finding of report.findings) {
    report.summary[finding.severity] += 1;
  }
  report.summary.wafDetected = report.waf.detected;
  report.summary.httpsAvailable = Boolean(report.tls?.ok);
  report.summary.subdomainsFound = report.subdomains.length;
  report.summary.subdomainsTested = countTestedSubdomains(report.pages, rootDomain, baseHost);
  report.finishedAt = new Date().toISOString();
  return report;
}

function addPageToReport(report, page, scannedOrigins) {
  report.pages.push(page);
  report.findings.push(...page.findings);
  mergeWaf(report.waf, page.waf);
  try {
    scannedOrigins.add(new URL(page.finalUrl || page.url).origin);
  } catch {
    // Partial page records can still be useful as findings.
  }
}

function countTestedSubdomains(pages, rootDomain, baseHost) {
  const hosts = new Set();
  for (const page of pages) {
    try {
      const host = new URL(page.url).hostname.toLowerCase();
      if (host !== baseHost && isSubdomainOf(host, rootDomain)) hosts.add(host);
    } catch {
      // Ignore malformed URLs in partial page records.
    }
  }
  return hosts.size;
}

async function discoverSubdomains(rootDomain, baseHost, timeoutMs, signal) {
  const sources = [];
  const sourceByHost = new Map();
  const [
    ctNames,
    otxNames,
    hackerTargetNames,
    rapidDnsNames,
    zoneTransferNames
  ] = await Promise.all([
    discoverFromCertificateTransparency(rootDomain, timeoutMs, signal),
    discoverFromOtx(rootDomain, timeoutMs, signal),
    discoverFromHackerTarget(rootDomain, timeoutMs, signal),
    discoverFromRapidDns(rootDomain, timeoutMs, signal),
    discoverFromZoneTransfer(rootDomain, timeoutMs)
  ]);
  const wordlistNames = COMMON_SUBDOMAINS.map((name) => `${name}.${rootDomain}`.toLowerCase());

  addSourceNames(sourceByHost, "certificate-transparency", ctNames);
  addSourceNames(sourceByHost, "alienvault-otx", otxNames);
  addSourceNames(sourceByHost, "hackertarget", hackerTargetNames);
  addSourceNames(sourceByHost, "rapiddns", rapidDnsNames);
  addSourceNames(sourceByHost, "zone-transfer", zoneTransferNames);
  addSourceNames(sourceByHost, "dns-wordlist", wordlistNames);

  for (const [name, names] of [
    ["certificate-transparency", ctNames],
    ["alienvault-otx", otxNames],
    ["hackertarget", hackerTargetNames],
    ["rapiddns", rapidDnsNames],
    ["zone-transfer", zoneTransferNames],
    ["dns-wordlist", wordlistNames]
  ]) {
    sources.push({ name, count: names.length });
  }

  const candidates = [...sourceByHost.keys()]
    .filter((host) => host !== baseHost && isSubdomainOf(host, rootDomain))
    .slice(0, MAX_DISCOVERY_NAMES);
  const foundByHost = new Map();
  const concurrency = 10;
  let cursor = 0;

  async function worker() {
    while (cursor < candidates.length) {
      throwIfAborted(signal);
      const host = candidates[cursor++];
      const result = await resolveHostPublic(host, timeoutMs, signal);
      const sourcesForHost = [...(sourceByHost.get(host) || [])];
      if (result) {
        foundByHost.set(host, { ...result, sources: sourcesForHost, dnsStatus: "resolvido" });
      } else if (sourcesForHost.some((source) => source !== "dns-wordlist")) {
        foundByHost.set(host, {
          host,
          addresses: [],
          recordTypes: [],
          resolvers: [],
          sources: sourcesForHost,
          dnsStatus: "publicado em fonte passiva, sem A/AAAA confirmado"
        });
      }
    }
  }

  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  return {
    subdomains: [...foundByHost.values()].sort((a, b) => a.host.localeCompare(b.host)),
    sources
  };
}

function addSourceNames(target, source, names) {
  for (const name of names) {
    if (!target.has(name)) target.set(name, new Set());
    target.get(name).add(source);
  }
}

async function discoverFromCertificateTransparency(rootDomain, timeoutMs, signal) {
  const endpoint = `https://crt.sh/?q=${encodeURIComponent(`%.${rootDomain}`)}&output=json`;
  try {
    const response = await fetchWithTimeout(endpoint, Math.max(timeoutMs, 12000), { redirect: "follow", signal });
    if (!response.ok) return [];
    const records = await response.json();
    const names = new Set();
    for (const record of records) {
      const value = String(record.name_value || "");
      for (const line of value.split(/\s+/)) {
        const host = normalizeDiscoveredHost(line, rootDomain);
        if (host) names.add(host);
      }
    }
    return [...names].slice(0, MAX_CT_NAMES);
  } catch {
    throwIfAborted(signal);
    return [];
  }
}

async function discoverFromOtx(rootDomain, timeoutMs, signal) {
  const endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(rootDomain)}/passive_dns`;
  try {
    const response = await fetchWithTimeout(endpoint, Math.max(timeoutMs, 12000), { redirect: "follow", signal });
    if (!response.ok) return [];
    const payload = await response.json();
    const names = new Set();
    for (const record of Array.isArray(payload.passive_dns) ? payload.passive_dns : []) {
      for (const value of [record.hostname, record.address]) {
        const host = normalizeDiscoveredHost(String(value || ""), rootDomain);
        if (host) names.add(host);
      }
    }
    return [...names];
  } catch {
    return [];
  }
}

async function discoverFromHackerTarget(rootDomain, timeoutMs, signal) {
  const endpoint = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(rootDomain)}`;
  try {
    const response = await fetchWithTimeout(endpoint, Math.max(timeoutMs, 12000), { redirect: "follow", signal });
    if (!response.ok) return [];
    const text = await response.text();
    return extractHostsFromText(text, rootDomain);
  } catch {
    return [];
  }
}

async function discoverFromRapidDns(rootDomain, timeoutMs, signal) {
  const endpoint = `https://rapiddns.io/subdomain/${encodeURIComponent(rootDomain)}?full=1`;
  try {
    const response = await fetchWithTimeout(endpoint, Math.max(timeoutMs, 12000), { redirect: "follow", signal });
    if (!response.ok) return [];
    const text = await response.text();
    return extractHostsFromText(text, rootDomain);
  } catch {
    return [];
  }
}

async function discoverFromZoneTransfer(rootDomain, timeoutMs) {
  let nameServers = [];
  try {
    nameServers = await dns.resolveNs(rootDomain);
  } catch {
    return [];
  }

  const names = new Set();
  for (const ns of nameServers.slice(0, 8)) {
    try {
      const { stdout } = await execFileAsync("nslookup", ["-type=any", "-querytype=AXFR", rootDomain, ns], {
        timeout: Math.max(timeoutMs, 10000),
        windowsHide: true,
        maxBuffer: 1024 * 1024
      });
      for (const host of extractHostsFromText(stdout, rootDomain)) {
        names.add(host);
      }
    } catch {
      // Most public DNS servers block AXFR; that is expected.
    }
  }
  return [...names];
}

function extractHostsFromText(text, rootDomain) {
  const names = new Set();
  const escaped = rootDomain.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const regex = new RegExp(`(?:[a-z0-9_-]+\\.)+${escaped}`, "gi");
  for (const match of String(text || "").matchAll(regex)) {
    const host = normalizeDiscoveredHost(match[0], rootDomain);
    if (host) names.add(host);
  }
  return [...names];
}

async function resolveHostPublic(host, timeoutMs, signal) {
  const [system, googleA, googleAaaa, cloudflareA, cloudflareAaaa] = await Promise.all([
    resolveHostSystem(host),
    resolveHostDoh("https://dns.google/resolve", host, "A", timeoutMs, signal),
    resolveHostDoh("https://dns.google/resolve", host, "AAAA", timeoutMs, signal),
    resolveHostDoh("https://cloudflare-dns.com/dns-query", host, "A", timeoutMs, signal),
    resolveHostDoh("https://cloudflare-dns.com/dns-query", host, "AAAA", timeoutMs, signal)
  ]);

  const addresses = new Set();
  const recordTypes = new Set();
  const resolvers = new Set();
  for (const result of [system, googleA, googleAaaa, cloudflareA, cloudflareAaaa].flat()) {
    if (!result) continue;
    addresses.add(result.address);
    recordTypes.add(result.type);
    resolvers.add(result.resolver);
  }

  if (!addresses.size) return null;
  return {
    host,
    addresses: [...addresses],
    recordTypes: [...recordTypes],
    resolvers: [...resolvers]
  };
}

async function resolveHostSystem(host) {
  try {
    const records = await dns.lookup(host, { all: true });
    return records.map((record) => ({
      address: record.address,
      type: record.family === 6 ? "AAAA" : "A",
      resolver: "system"
    }));
  } catch {
    return [];
  }
}

async function resolveHostDoh(resolverUrl, host, type, timeoutMs, signal) {
  try {
    const url = new URL(resolverUrl);
    url.searchParams.set("name", host);
    url.searchParams.set("type", type);
    const response = await fetchWithTimeout(url.href, timeoutMs, {
      signal,
      headers: { "accept": "application/dns-json" }
    });
    if (!response.ok) return [];
    const payload = await response.json();
    const answers = Array.isArray(payload.Answer) ? payload.Answer : [];
    return answers
      .filter((answer) => answer.data && (answer.type === 1 || answer.type === 28))
      .map((answer) => ({
        address: answer.data,
        type: answer.type === 28 ? "AAAA" : "A",
        resolver: resolverUrl.includes("google") ? "google-public-dns" : "cloudflare-public-dns"
      }));
  } catch {
    return [];
  }
}

async function inspectPage(url, timeoutMs, signal, appProfile) {
  const page = {
    url: url.href,
    finalUrl: url.href,
    status: null,
    responseTimeMs: null,
    title: "",
    headers: {},
    tls: null,
    httpsRedirect: null,
    technologies: [],
    cookies: [],
    links: [],
    waf: { detected: false, vendors: [], evidence: [] },
    findings: [],
    error: null
  };

  const started = Date.now();
  try {
    const [tlsInfo, redirectInfo] = await Promise.all([
      inspectTls(url.hostname, timeoutMs),
      inspectHttpsRedirect(url.hostname, timeoutMs, signal)
    ]);
    page.tls = tlsInfo;
    page.httpsRedirect = redirectInfo;

    throwIfAborted(signal);
    const response = await fetchWithTimeout(url.href, timeoutMs, { redirect: "follow", signal });
    page.responseTimeMs = Date.now() - started;
    page.status = response.status;
    page.finalUrl = response.url;
    page.headers = headersToObject(response.headers);
    page.waf = detectWaf(page.headers, page.status);
    page.technologies = detectTechnologies(page.headers);
    page.cookies = parseCookies(response.headers.getSetCookie?.() || splitSetCookie(response.headers.get("set-cookie")));

    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("text/html")) {
      const body = await readLimitedBody(response);
      page.title = extractTitle(body);
      page.links = extractLinks(body, new URL(page.finalUrl));
      page.findings.push(...inspectHtml(body, page.finalUrl));
    }

    page.findings.push(...inspectHeaders(page.headers, page.url, page.status));
    page.findings.push(...inspectCookies(page.cookies, page.url));
    page.findings.push(...inspectPageTransport(page));
    page.findings.push(...inspectApplicationProfile(page, appProfile));
    page.findings.push(...await inspectHttpMethods(new URL(page.finalUrl || page.url), timeoutMs, signal));
    page.findings.push(...await inspectKnownExposures(new URL(page.finalUrl || page.url), timeoutMs, signal));
    page.findings.push(...await inspectSecurityTxt(new URL(page.finalUrl || page.url), timeoutMs, signal));
  } catch (error) {
    if (signal?.aborted || error.name === "AbortError") throw error;
    page.error = String(error.message || error);
    page.findings.push(finding("medium", "Falha ao acessar URL", page.url, page.error, "Verifique DNS, conectividade, bloqueio por rede ou certificado."));
  }

  return page;
}

function inspectHeaders(headers, url, status) {
  const findings = [];
  const has = (name) => Boolean(headers[name.toLowerCase()]);
  if (status && status >= 500) {
    findings.push(finding("medium", "Resposta 5xx", url, `A URL respondeu HTTP ${status}.`, "Investigue erro de aplicacao ou indisponibilidade."));
  }
  if (!has("strict-transport-security")) {
    findings.push(finding("medium", "HSTS ausente", url, "O header Strict-Transport-Security nao foi encontrado.", "Ative HSTS em paginas HTTPS para reduzir risco de downgrade."));
  }
  if (!has("content-security-policy")) {
    findings.push(finding("medium", "CSP ausente", url, "O header Content-Security-Policy nao foi encontrado.", "Defina uma CSP compativel com a aplicacao para reduzir impacto de XSS."));
  }
  if (!has("x-frame-options") && !frameAncestors(headers["content-security-policy"])) {
    findings.push(finding("low", "Protecao contra clickjacking ausente", url, "Nao foi encontrado X-Frame-Options nem frame-ancestors na CSP.", "Bloqueie ou restrinja embeds em frames."));
  }
  if (!has("x-content-type-options")) {
    findings.push(finding("low", "X-Content-Type-Options ausente", url, "O header nosniff nao foi encontrado.", "Adicione X-Content-Type-Options: nosniff."));
  }
  if (!has("referrer-policy")) {
    findings.push(finding("low", "Referrer-Policy ausente", url, "A politica de referrer nao foi declarada.", "Use uma politica como strict-origin-when-cross-origin."));
  }
  if (!has("permissions-policy")) {
    findings.push(finding("info", "Permissions-Policy ausente", url, "Nao ha restricao explicita de APIs do navegador.", "Declare Permissions-Policy conforme recursos usados."));
  }
  if (headers["strict-transport-security"]) {
    const maxAge = Number((headers["strict-transport-security"].match(/max-age=(\d+)/i) || [])[1] || 0);
    if (maxAge > 0 && maxAge < 15_552_000) {
      findings.push(finding("low", "HSTS com max-age baixo", url, `Strict-Transport-Security usa max-age=${maxAge}.`, "Use max-age de pelo menos 15552000 segundos; idealmente 31536000."));
    }
    if (!/includesubdomains/i.test(headers["strict-transport-security"])) {
      findings.push(finding("info", "HSTS sem includeSubDomains", url, "O HSTS nao cobre subdominios.", "Avalie incluir includeSubDomains apos validar todo o dominio."));
    }
  }
  if (headers["content-security-policy"]) {
    const csp = headers["content-security-policy"];
    if (/'unsafe-eval'/i.test(csp)) {
      findings.push(finding("medium", "CSP permite unsafe-eval", url, "A CSP contem 'unsafe-eval'.", "Remova unsafe-eval para reduzir superficie de XSS."));
    }
    if (/'unsafe-inline'/i.test(csp)) {
      findings.push(finding("low", "CSP permite unsafe-inline", url, "A CSP contem 'unsafe-inline'.", "Prefira nonces ou hashes para scripts e estilos inline."));
    }
  }
  if (headers["access-control-allow-origin"] === "*" && /true/i.test(headers["access-control-allow-credentials"] || "")) {
    findings.push(finding("high", "CORS com credenciais e wildcard", url, "Access-Control-Allow-Origin: * com credenciais habilitadas.", "Restrinja origins permitidas e remova wildcard para respostas autenticadas."));
  } else if (headers["access-control-allow-origin"] === "*") {
    findings.push(finding("info", "CORS wildcard", url, "Access-Control-Allow-Origin permite qualquer origem.", "Confirme se a resposta nao expoe dados sensiveis."));
  }
  if (!has("cross-origin-opener-policy")) {
    findings.push(finding("info", "COOP ausente", url, "Cross-Origin-Opener-Policy nao foi encontrado.", "Considere COOP para reduzir riscos de isolamento entre janelas."));
  }
  for (const header of ["server", "x-powered-by", "x-aspnet-version"]) {
    if (headers[header]) {
      findings.push(finding("info", "Divulgacao de tecnologia", url, `${header}: ${headers[header]}`, "Reduza banners e versoes expostas quando possivel."));
    }
  }
  return findings;
}

function inspectPageTransport(page) {
  const findings = [];
  if (page.tls && !page.tls.ok) {
    findings.push(finding("high", "HTTPS indisponivel ou inacessivel", page.url, page.tls.error || "Nao foi possivel validar TLS.", "Corrija HTTPS/TLS neste host."));
  } else if (page.tls && page.tls.ok) {
    if (!page.tls.authorized) {
      findings.push(finding("high", "Certificado TLS nao confiavel", page.url, page.tls.authorizationError || "Certificado nao autorizado.", "Corrija cadeia, validade e nomes do certificado."));
    }
    const days = daysUntil(page.tls.validTo);
    if (days !== null && days < 0) {
      findings.push(finding("high", "Certificado TLS expirado", page.url, `Expirou em ${page.tls.validTo}.`, "Renove o certificado imediatamente."));
    } else if (days !== null && days <= 30) {
      findings.push(finding("medium", "Certificado TLS perto de expirar", page.url, `Expira em ${Math.ceil(days)} dias (${page.tls.validTo}).`, "Planeje a renovacao do certificado."));
    }
  }
  if (page.httpsRedirect && !page.httpsRedirect.ok) {
    findings.push(finding("medium", "Redirect HTTP para HTTPS ausente", page.url, "A raiz HTTP deste host nao redirecionou claramente para HTTPS.", "Configure redirect 301/308 de HTTP para HTTPS."));
  }
  return findings;
}

function inspectApplicationProfile(page, appProfile) {
  if (!appProfile) return [];
  const findings = [];
  const url = page.url;
  const headers = page.headers || {};
  const tech = page.technologies || [];
  const csp = headers["content-security-policy"] || "";
  const cache = headers["cache-control"] || "";

  if (!csp) {
    findings.push(finding("medium", "Aplicacao sem CSP", url, "Nao ha Content-Security-Policy em resposta de aplicacao.", "Adote CSP por aplicacao; OWASP recomenda CSP como camada de defesa contra XSS."));
  } else {
    if (!/object-src\s+'none'/i.test(csp)) {
      findings.push(finding("low", "CSP sem object-src 'none'", url, "A CSP nao declara object-src 'none'.", "Bloqueie plugins legados com object-src 'none'."));
    }
    if (!/base-uri\s+'none'|base-uri\s+'self'/i.test(csp)) {
      findings.push(finding("low", "CSP sem base-uri restritivo", url, "A CSP nao restringe base-uri.", "Use base-uri 'none' ou 'self' para reduzir abuso de tags base."));
    }
    if (!/require-trusted-types-for\s+'script'/i.test(csp)) {
      findings.push(finding("info", "Trusted Types nao habilitado", url, "A CSP nao exige Trusted Types para scripts.", "Em apps React/Angular/Vue/SPA, avalie require-trusted-types-for 'script' onde suportado."));
    }
  }

  if (!headers["cross-origin-resource-policy"]) {
    findings.push(finding("info", "CORP ausente", url, "Cross-Origin-Resource-Policy nao foi encontrado.", "Avalie CORP para reduzir vazamentos cross-origin em aplicacoes modernas."));
  }
  if (!headers["cross-origin-embedder-policy"]) {
    findings.push(finding("info", "COEP ausente", url, "Cross-Origin-Embedder-Policy nao foi encontrado.", "Avalie COEP se a aplicacao precisa de isolamento forte de contexto."));
  }
  if (page.status === 200 && /text\/html/i.test(headers["content-type"] || "") && !/no-store|no-cache|private/i.test(cache)) {
    findings.push(finding("info", "HTML sem politica clara de cache", url, `Cache-Control: ${cache || "ausente"}`, "Defina cache de HTML conscientemente; assets versionados podem ter cache longo, HTML normalmente exige cache curto ou revalidacao."));
  }
  if (JSON.stringify(headers).toLowerCase().includes("debug") || /debug|development|dev mode/i.test(page.title || "")) {
    findings.push(finding("medium", "Possivel modo debug/desenvolvimento exposto", url, "Headers ou titulo indicam debug/desenvolvimento.", "Garanta build de producao e desative paginas/flags de debug."));
  }
  if (!tech.length) {
    findings.push(finding("info", "Framework nao identificado por resposta", url, "Nao foi possivel inferir framework por headers conhecidos.", "Isso pode ser positivo; complemente com SAST/DAST autenticado para validar configuracoes internas."));
  }
  if (appProfile !== "generic") {
    findings.push(...inspectFrameworkSpecificHints(page, appProfile));
  }
  return findings;
}

function inspectFrameworkSpecificHints(page, appProfile) {
  const findings = [];
  const url = page.url;
  const headersText = JSON.stringify(page.headers || {}).toLowerCase();
  const title = (page.title || "").toLowerCase();
  const text = `${headersText} ${title}`;
  const checks = {
    next: ["next", "verifique se headers sao definidos em next.config, middleware ou camada de borda."],
    react: ["react", "garanta build de producao, CSP, Trusted Types quando possivel e evite dangerouslySetInnerHTML sem sanitizacao."],
    angular: ["angular", "garanta build de producao, sanitizacao padrao ativa, CSP e Trusted Types quando possivel."],
    vue: ["vue", "garanta build de producao, CSP e cuidado com v-html sem sanitizacao."],
    django: ["django", "confirme SECURE_SSL_REDIRECT, CSRF_COOKIE_SECURE, SESSION_COOKIE_SECURE e ALLOWED_HOSTS no backend."],
    rails: ["rails", "confirme force_ssl, cookies secure/httponly/samesite e protecoes padrao de CSRF ativas."],
    laravel: ["laravel", "confirme APP_DEBUG=false, cookies secure e configuracao de trusted proxies/HTTPS."],
    spring: ["spring", "confirme Spring Security headers, CSRF quando aplicavel e cookies secure."]
  };
  const [needle, recommendation] = checks[appProfile] || checks.generic || [];
  if (needle && !text.includes(needle)) {
    findings.push(finding("info", "Framework selecionado nao confirmado externamente", url, `Perfil escolhido: ${appProfile}.`, recommendation));
  }
  return findings;
}

async function inspectHttpMethods(url, timeoutMs, signal) {
  try {
    const response = await fetchWithTimeout(url.origin, timeoutMs, { method: "OPTIONS", redirect: "manual", signal });
    const allow = response.headers.get("allow") || response.headers.get("access-control-allow-methods") || "";
    if (!allow) return [];
    const risky = allow.toUpperCase().split(/,\s*/).filter((method) => ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"].includes(method));
    if (!risky.length) return [];
    const severity = risky.includes("TRACE") || risky.includes("CONNECT") ? "high" : "medium";
    return [finding(severity, "Metodos HTTP sensiveis anunciados", url.origin, `Allow: ${allow}`, "Restrinja metodos HTTP aos necessarios para a aplicacao.")];
  } catch {
    return [];
  }
}

async function inspectKnownExposures(url, timeoutMs, signal) {
  const probes = [
    { path: "/.env", title: "Arquivo .env exposto" },
    { path: "/.git/config", title: "Repositorio Git exposto" },
    { path: "/config.php.bak", title: "Backup de configuracao exposto" },
    { path: "/backup.zip", title: "Arquivo de backup exposto" }
  ];
  const findings = [];
  for (const probe of probes) {
    try {
      throwIfAborted(signal);
      const target = new URL(probe.path, url.origin);
      const response = await fetchWithTimeout(target.href, timeoutMs, { method: "GET", redirect: "manual", signal });
      const contentType = response.headers.get("content-type") || "";
      if (response.status === 200 && !contentType.includes("text/html")) {
        findings.push(finding("high", probe.title, target.href, `HTTP 200; content-type: ${contentType || "nao informado"}`, "Remova o arquivo da raiz publica e revise exposicao de segredos."));
      }
    } catch (error) {
      if (signal?.aborted || error.name === "AbortError") throw error;
      // Missing or blocked probes are normal.
    }
  }
  return findings;
}

async function inspectSecurityTxt(url, timeoutMs, signal) {
  try {
    const target = new URL("/.well-known/security.txt", url.origin);
    const response = await fetchWithTimeout(target.href, timeoutMs, { method: "GET", redirect: "manual", signal });
    if (response.status === 404) {
      return [finding("info", "security.txt ausente", target.href, "Nao foi encontrado /.well-known/security.txt.", "Publique um security.txt para orientar reporte responsavel de vulnerabilidades.")];
    }
    if (response.status >= 200 && response.status < 300) return [];
  } catch (error) {
    if (signal?.aborted || error.name === "AbortError") throw error;
    return [];
  }
  return [];
}

function inspectCookies(cookies, url) {
  const findings = [];
  for (const cookie of cookies) {
    if (!cookie.secure) {
      findings.push(finding("medium", "Cookie sem Secure", url, `${cookie.name} nao possui atributo Secure.`, "Marque cookies sensiveis como Secure."));
    }
    if (!cookie.httpOnly) {
      findings.push(finding("low", "Cookie sem HttpOnly", url, `${cookie.name} nao possui atributo HttpOnly.`, "Use HttpOnly em cookies nao acessados por JavaScript."));
    }
    if (!cookie.sameSite) {
      findings.push(finding("low", "Cookie sem SameSite", url, `${cookie.name} nao declara SameSite.`, "Declare SameSite=Lax ou Strict quando compativel."));
    }
  }
  return findings;
}

function inspectHtml(body, url) {
  const findings = [];
  if (/<input[^>]+type=["']?password/i.test(body) && !/<form[^>]+autocomplete=["']?(off|new-password)/i.test(body)) {
    findings.push(finding("info", "Formulario de senha detectado", url, "Ha campo de senha na pagina.", "Revise autocomplete, MFA, rate limit e protecoes de login."));
  }
  if (/http:\/\/[^"'\s<>]+/i.test(body)) {
    findings.push(finding("low", "Conteudo HTTP referenciado", url, "A pagina referencia recursos via HTTP.", "Prefira HTTPS para evitar mixed content."));
  }
  return findings;
}

async function inspectTls(hostname, timeoutMs) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false,
      timeout: timeoutMs
    });
    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate();
      resolve({
        ok: true,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError || null,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name || null,
        validFrom: cert.valid_from || null,
        validTo: cert.valid_to || null,
        issuer: cert.issuer?.O || cert.issuer?.CN || null,
        subject: cert.subject?.CN || null
      });
      socket.end();
    });
    socket.once("timeout", () => {
      socket.destroy();
      resolve({ ok: false, error: "Timeout ao conectar na porta 443." });
    });
    socket.once("error", (error) => resolve({ ok: false, error: String(error.message || error) }));
  });
}

async function inspectHttpsRedirect(hostname, timeoutMs, signal) {
  try {
    const response = await fetchWithTimeout(`http://${hostname}/`, timeoutMs, { redirect: "manual", signal });
    const location = response.headers.get("location") || "";
    return {
      ok: response.status >= 300 && response.status < 400 && location.startsWith("https://"),
      status: response.status,
      location
    };
  } catch (error) {
    return { ok: false, error: String(error.message || error) };
  }
}

async function inspectPublicDns(rootDomain, timeoutMs = 9000) {
  const records = {
    domain: rootDomain,
    ns: [],
    mx: [],
    txt: [],
    soa: null,
    caa: [],
    errors: []
  };

  await Promise.all([
    collectDns(records, "ns", () => withTimeout(dns.resolveNs(rootDomain), timeoutMs, "Timeout em NS")),
    collectDns(records, "mx", () => withTimeout(dns.resolveMx(rootDomain), timeoutMs, "Timeout em MX")),
    collectDns(records, "txt", async () => (await withTimeout(dns.resolveTxt(rootDomain), timeoutMs, "Timeout em TXT")).map((entry) => entry.join(""))),
    collectDns(records, "soa", () => withTimeout(dns.resolveSoa(rootDomain), timeoutMs, "Timeout em SOA")),
    collectDns(records, "caa", () => withTimeout(dns.resolveCaa(rootDomain), timeoutMs, "Timeout em CAA"))
  ]);

  return records;
}

async function collectDns(records, key, resolver) {
  try {
    records[key] = await resolver();
  } catch (error) {
    records.errors.push(`${key}: ${error.code || error.message || error}`);
  }
}

async function runWafProbes(targetUrl, timeoutMs, signal) {
  const probes = [
    { name: "baseline", path: "/?scan_probe=baseline" },
    { name: "xss-query", path: "/?scan_probe=%3Cscript%3Ealert(1)%3C%2Fscript%3E" },
    { name: "sqli-query", path: "/?scan_probe=%27%20OR%20%271%27%3D%271" }
  ];
  const results = [];
  for (const probe of probes) {
    const url = new URL(probe.path, targetUrl.origin);
    try {
      throwIfAborted(signal);
      const response = await fetchWithTimeout(url.href, timeoutMs, { redirect: "manual", signal });
      const headers = headersToObject(response.headers);
      const waf = detectWaf(headers, response.status);
      const suspicious = waf.detected || [403, 406, 412, 418, 429].includes(response.status);
      results.push({
        name: probe.name,
        url: url.href,
        status: response.status,
        suspicious,
        evidence: suspicious ? `${probe.name}: HTTP ${response.status}${waf.evidence.length ? `; ${waf.evidence.join("; ")}` : ""}` : "Sem bloqueio aparente"
      });
    } catch (error) {
      if (signal?.aborted || error.name === "AbortError") throw error;
      results.push({ name: probe.name, url: url.href, status: null, suspicious: false, evidence: String(error.message || error) });
    }
  }
  return results;
}

function addGlobalFindings(report) {
  if (report.tls && !report.tls.ok) {
    report.findings.push(finding("high", "HTTPS indisponivel ou inacessivel", report.target, report.tls.error || "Nao foi possivel validar TLS.", "Habilite HTTPS valido para o dominio."));
  } else if (report.tls && report.tls.ok && !report.tls.authorized) {
    report.findings.push(finding("high", "Certificado TLS nao confiavel", report.target, report.tls.authorizationError || "Certificado nao autorizado.", "Corrija a cadeia, validade e nome do certificado."));
  }
  if (report.httpsRedirect && !report.httpsRedirect.ok) {
    report.findings.push(finding("medium", "Redirect HTTP para HTTPS ausente", report.target, "A raiz HTTP nao redirecionou claramente para HTTPS.", "Configure redirect 301/308 de HTTP para HTTPS."));
  }
  if (!report.waf.detected) {
    report.findings.push(finding("info", "WAF nao identificado", report.target, "Nao foram encontrados sinais claros de WAF/CDN de seguranca.", "Confirme se ha WAF ativo no provedor ou valide com testes autorizados mais profundos."));
  }
}

function detectWaf(headers, status) {
  const indicators = [
    ["cloudflare", ["cf-ray", "cf-cache-status", "server:cloudflare"]],
    ["sucuri", ["x-sucuri-id", "x-sucuri-cache", "server:sucuri"]],
    ["akamai", ["akamai-grn", "x-akamai", "server:akamai"]],
    ["aws cloudfront", ["x-amz-cf-id", "x-amz-cf-pop", "via:cloudfront"]],
    ["imperva/incapsula", ["x-iinfo", "x-cdn:incapsula", "visid_incap"]],
    ["fastly", ["fastly-debug-digest", "x-served-by", "server:fastly"]],
    ["azure front door", ["x-azure-ref", "x-cache:config_nocache"]],
    ["f5/big-ip", ["x-wa-info", "bigipserver"]]
  ];
  const flat = Object.entries(headers).map(([key, value]) => `${key}:${value}`.toLowerCase());
  const vendors = new Set();
  const evidence = [];
  for (const [vendor, keys] of indicators) {
    for (const key of keys) {
      const needle = key.toLowerCase();
      const hit = flat.find((entry) => entry.includes(needle));
      if (hit) {
        vendors.add(vendor);
        evidence.push(hit);
      }
    }
  }
  if ([403, 406, 412, 429].includes(status)) {
    evidence.push(`status:${status}`);
  }
  return { detected: vendors.size > 0, vendors: [...vendors], evidence };
}

function detectTechnologies(headers) {
  const tech = new Set();
  const text = JSON.stringify(headers).toLowerCase();
  if (text.includes("wordpress")) tech.add("WordPress");
  if (text.includes("php")) tech.add("PHP");
  if (text.includes("asp.net") || text.includes("iis")) tech.add("ASP.NET/IIS");
  if (text.includes("nginx")) tech.add("Nginx");
  if (text.includes("apache")) tech.add("Apache");
  if (text.includes("cloudflare")) tech.add("Cloudflare");
  return [...tech];
}

function mergeWaf(target, source) {
  if (source.detected) target.detected = true;
  target.vendors = [...new Set([...target.vendors, ...source.vendors])];
  target.evidence = [...new Set([...target.evidence, ...source.evidence])].slice(0, 30);
}

function headersToObject(headers) {
  const result = {};
  headers.forEach((value, key) => {
    result[key.toLowerCase()] = value;
  });
  return result;
}

async function readLimitedBody(response) {
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks = [];
  let total = 0;
  while (total < MAX_BODY_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.length;
  }
  return Buffer.concat(chunks).toString("utf8");
}

function extractLinks(body, baseUrl) {
  const links = new Set();
  const hrefRegex = /href\s*=\s*["']([^"']+)["']/gi;
  let match;
  while ((match = hrefRegex.exec(body))) {
    const raw = match[1].trim();
    if (!raw || raw.startsWith("#") || raw.startsWith("mailto:") || raw.startsWith("tel:") || raw.startsWith("javascript:")) continue;
    try {
      const url = new URL(raw, baseUrl);
      url.hash = "";
      if (["http:", "https:"].includes(url.protocol)) links.add(url.href);
    } catch {
      // Ignore malformed links in scanned pages.
    }
  }
  return [...links];
}

function extractTitle(body) {
  const match = body.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? cleanText(match[1]).slice(0, 140) : "";
}

function parseCookies(values) {
  return values.filter(Boolean).map((value) => {
    const parts = value.split(";").map((part) => part.trim());
    const [name] = parts[0].split("=");
    const attrs = parts.slice(1).map((part) => part.toLowerCase());
    const sameSite = attrs.find((part) => part.startsWith("samesite="));
    return {
      name: name || "(sem nome)",
      secure: attrs.includes("secure"),
      httpOnly: attrs.includes("httponly"),
      sameSite: sameSite ? sameSite.split("=")[1] : ""
    };
  });
}

function splitSetCookie(header) {
  if (!header) return [];
  return header.split(/,(?=\s*[^;,]+=)/g);
}

function normalizeTarget(target) {
  if (!target || typeof target !== "string") {
    throw httpError(400, "Informe um dominio ou URL.");
  }
  const trimmed = target.trim();
  const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let url;
  try {
    url = new URL(withProtocol);
  } catch {
    throw httpError(400, "Dominio ou URL invalido.");
  }
  if (!["http:", "https:"].includes(url.protocol) || !url.hostname.includes(".")) {
    throw httpError(400, "Use uma URL HTTP/HTTPS valida.");
  }
  url.hash = "";
  return url;
}

function isAllowedHost(hostname, baseHost, rootDomain, includeSubdomains) {
  const host = hostname.toLowerCase();
  if (host === baseHost) return true;
  return includeSubdomains && (host === rootDomain || host.endsWith(`.${rootDomain}`));
}

function normalizeDiscoveredHost(value, rootDomain) {
  const host = value
    .trim()
    .toLowerCase()
    .replace(/^\*\./, "")
    .replace(/\.$/, "");
  if (!host || host.includes("*") || host.includes("@")) return "";
  if (!/^[a-z0-9.-]+$/.test(host)) return "";
  if (!isSubdomainOf(host, rootDomain)) return "";
  return host;
}

function isSubdomainOf(host, rootDomain) {
  return host !== rootDomain && host.endsWith(`.${rootDomain}`);
}

function getRootDomain(hostname) {
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  const lastTwo = parts.slice(-2).join(".");
  const commonPublicSuffixes = new Set([
    "com.br",
    "net.br",
    "org.br",
    "gov.br",
    "edu.br",
    "jus.br",
    "mil.br",
    "nom.br",
    "co.uk",
    "org.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "co.jp",
    "com.mx",
    "com.ar",
    "com.co"
  ]);
  if (commonPublicSuffixes.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return lastTwo;
}

function frameAncestors(csp) {
  return typeof csp === "string" && /frame-ancestors/i.test(csp);
}

function cleanText(value) {
  return value.replace(/\s+/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").trim();
}

async function loadEnvFile(envPath) {
  try {
    const raw = await fs.readFile(envPath, "utf8");
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) continue;
      const index = trimmed.indexOf("=");
      const key = trimmed.slice(0, index).trim();
      let value = trimmed.slice(index + 1).trim();
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      if (key && process.env[key] === undefined) process.env[key] = value;
    }
  } catch {
    // .env is optional; production can provide environment variables directly.
  }
}

function parseEmailRecipients(value) {
  const raw = Array.isArray(value) ? value.join(",") : String(value || "");
  const seen = new Set();
  return raw
    .split(/[,\n;]/)
    .map((email) => email.trim().toLowerCase())
    .filter((email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    .filter((email) => {
      if (seen.has(email)) return false;
      seen.add(email);
      return true;
    })
    .slice(0, 30);
}

async function sendSmtpMail({ to, subject, html, text }) {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  const username = process.env.SMTP_USER || "";
  const password = process.env.SMTP_PASS || "";
  const secure = process.env.SMTP_SECURE === "true" || port === 465;
  const startTls = !secure && process.env.SMTP_STARTTLS !== "false";

  if (!host || !from) {
    throw new Error("SMTP_HOST e SMTP_FROM precisam estar configurados para envio de e-mail.");
  }

  const client = await createSmtpClient({ host, port, secure });
  try {
    await client.expect(220);
    await client.command(`EHLO ${process.env.SMTP_HELO || "scan-dominio.local"}`, 250);
    if (startTls) {
      await client.command("STARTTLS", 220);
      client.upgradeToTls(host);
      await client.command(`EHLO ${process.env.SMTP_HELO || "scan-dominio.local"}`, 250);
    }
    if (username && password) {
      await client.command("AUTH LOGIN", 334);
      await client.command(Buffer.from(username).toString("base64"), 334);
      await client.command(Buffer.from(password).toString("base64"), 235);
    }
    await client.command(`MAIL FROM:<${from}>`, 250);
    for (const recipient of to) {
      await client.command(`RCPT TO:<${recipient}>`, [250, 251]);
    }
    await client.command("DATA", 354);
    await client.command(buildEmailMessage({ from, to, subject, html, text }), 250);
    await client.command("QUIT", 221).catch(() => {});
  } finally {
    client.close();
  }
}

function createSmtpClient({ host, port, secure }) {
  let socket = secure
    ? tls.connect({ host, port, servername: host })
    : net.connect({ host, port });
  let buffer = "";
  const waiters = [];

  socket.setEncoding("utf8");
  socket.setTimeout(Number(process.env.SMTP_TIMEOUT_MS || 20000));
  socket.on("data", (chunk) => {
    buffer += chunk;
    flushSmtpWaiters();
  });
  socket.on("error", (error) => {
    while (waiters.length) waiters.shift().reject(error);
  });
  socket.on("timeout", () => {
    socket.destroy(new Error("Timeout ao conectar/enviar pelo SMTP."));
  });

  function flushSmtpWaiters() {
    const response = readSmtpResponse();
    if (!response || !waiters.length) return;
    const waiter = waiters.shift();
    waiter.resolve(response);
    flushSmtpWaiters();
  }

  function readSmtpResponse() {
    const lines = buffer.split(/\r?\n/);
    if (!buffer.endsWith("\n")) return null;
    const completeIndex = lines.findIndex((line) => /^\d{3}\s/.test(line));
    if (completeIndex === -1) return null;
    const responseLines = lines.slice(0, completeIndex + 1).filter(Boolean);
    buffer = lines.slice(completeIndex + 1).join("\n");
    const last = responseLines[responseLines.length - 1] || "";
    return {
      code: Number(last.slice(0, 3)),
      message: responseLines.join("\n")
    };
  }

  function expect(expected) {
    const allowed = Array.isArray(expected) ? expected : [expected];
    return new Promise((resolve, reject) => {
      waiters.push({
        resolve: (response) => {
          if (allowed.includes(response.code)) resolve(response);
          else reject(new Error(`SMTP respondeu ${response.code}: ${response.message}`));
        },
        reject
      });
      flushSmtpWaiters();
    });
  }

  return {
    expect,
    async command(commandText, expected) {
      socket.write(`${commandText}\r\n`);
      return expect(expected);
    },
    upgradeToTls(servername) {
      socket = tls.connect({ socket, servername });
      buffer = "";
      socket.setEncoding("utf8");
      socket.setTimeout(Number(process.env.SMTP_TIMEOUT_MS || 20000));
      socket.on("data", (chunk) => {
        buffer += chunk;
        flushSmtpWaiters();
      });
      socket.on("error", (error) => {
        while (waiters.length) waiters.shift().reject(error);
      });
      socket.on("timeout", () => {
        socket.destroy(new Error("Timeout ao conectar/enviar pelo SMTP."));
      });
    },
    close() {
      socket.end();
    }
  };
}

function buildEmailMessage({ from, to, subject, html, text }) {
  const boundary = `scan-dominio-${crypto.randomUUID()}`;
  const headers = [
    `From: ${formatMailAddress(from)}`,
    `To: ${to.map(formatMailAddress).join(", ")}`,
    `Subject: ${encodeMailHeader(subject)}`,
    "MIME-Version: 1.0",
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    "X-Mailer: SCAN-Dominio"
  ];
  const body = [
    `--${boundary}`,
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: 8bit",
    "",
    text,
    `--${boundary}`,
    "Content-Type: text/html; charset=utf-8",
    "Content-Transfer-Encoding: 8bit",
    "",
    html,
    `--${boundary}--`
  ].join("\r\n");
  return `${headers.join("\r\n")}\r\n\r\n${body}\r\n.`;
}

function formatMailAddress(email) {
  return `<${String(email).replace(/[<>\r\n]/g, "")}>`;
}

function encodeMailHeader(value) {
  return `=?UTF-8?B?${Buffer.from(String(value), "utf8").toString("base64")}?=`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function labelSeverity(value) {
  return {
    high: "Alto",
    medium: "Medio",
    low: "Baixo",
    info: "Info"
  }[value] || value;
}

function formatDateTime(value) {
  if (!value) return "-";
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "short",
    timeStyle: "medium"
  }).format(new Date(value));
}

function daysUntil(dateText) {
  if (!dateText) return null;
  const timestamp = Date.parse(dateText);
  if (!Number.isFinite(timestamp)) return null;
  return (timestamp - Date.now()) / 86_400_000;
}

function finding(severity, title, url, evidence, recommendation) {
  return { severity, title, url, evidence, recommendation };
}

function groupFindingsByUrl(findings) {
  const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
  const groups = new Map();
  for (const item of findings) {
    const url = item.url || "Sem URL";
    if (!groups.has(url)) groups.set(url, []);
    groups.get(url).push(item);
  }
  return [...groups.entries()].map(([url, items]) => ({
    url,
    findings: items.sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9))
  }));
}

function clamp(value, min, max) {
  if (!Number.isFinite(value)) return min;
  return Math.max(min, Math.min(max, Math.round(value)));
}

async function withTimeout(promise, timeoutMs, message) {
  let timeout;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new Error(message)), timeoutMs);
      })
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchWithTimeout(url, timeoutMs, options = {}) {
  const controller = new AbortController();
  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const abortFromParent = () => controller.abort();
  if (options.signal?.aborted) controller.abort();
  options.signal?.addEventListener("abort", abortFromParent, { once: true });
  const { signal, ...fetchOptions } = options;
  try {
    return await fetch(url, {
      ...fetchOptions,
      signal: controller.signal,
      headers: {
        "user-agent": USER_AGENT,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ...(fetchOptions.headers || {})
      }
    });
  } catch (error) {
    if (timedOut && !options.signal?.aborted) {
      throw new Error(`Timeout apos ${timeoutMs} ms`);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
    options.signal?.removeEventListener("abort", abortFromParent);
  }
}

function sendJson(res, status, payload) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  res.end(JSON.stringify(payload));
}

function httpError(statusCode, publicMessage) {
  const error = new Error(publicMessage);
  error.statusCode = statusCode;
  error.publicMessage = publicMessage;
  return error;
}
