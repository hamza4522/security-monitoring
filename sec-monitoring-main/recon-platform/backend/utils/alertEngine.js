'use strict';
/**
 * alertEngine.js — Alert Rule Evaluator & Multi-Channel Dispatcher
 *
 * Channels: Browser (WebSocket push), Webhook, Slack, Discord, Email (SMTP)
 * Rules are stored in-memory. History is stored in-memory (last 200 alerts).
 */

const https = require('https');
const http = require('http');

// ── In-Memory State ───────────────────────────────────────────────────────────

let _broadcastAll = null; // function(data) → sends to all connected WS clients

const _rules = [
  { id: 'rule-1', name: 'Critical Finding',      enabled: true, trigger: 'severity',    value: 'critical',  channels: ['browser'] },
  { id: 'rule-2', name: 'High Risk Score (≥70)',  enabled: true, trigger: 'risk_score',  value: 70,          channels: ['browser'] },
  { id: 'rule-3', name: 'Scan Complete',          enabled: true, trigger: 'scan_complete',value: null,       channels: ['browser'] },
  { id: 'rule-4', name: 'SQL Injection Found',    enabled: true, trigger: 'attack_type', value: 'sqli',      channels: ['browser'] },
  { id: 'rule-5', name: 'XSS Found',             enabled: true, trigger: 'attack_type', value: 'xss',       channels: ['browser'] },
  { id: 'rule-6', name: 'Dangerous Port Exposed', enabled: true, trigger: 'open_port',  value: null,        channels: ['browser'] },
];

const _history = []; // newest first, max 200

// Webhook configs (populated from API)
let _webhookConfig = { url: '', slack: '', discord: '', email: { host: '', port: 587, user: '', pass: '', to: '' } };

// ── Init ──────────────────────────────────────────────────────────────────────

function init(broadcastAllFn) {
  _broadcastAll = broadcastAllFn;
}

// ── Rule Management ───────────────────────────────────────────────────────────

function getRules() { return _rules; }

function updateRule(id, updates) {
  const rule = _rules.find(r => r.id === id);
  if (!rule) return null;
  Object.assign(rule, updates);
  return rule;
}

function addRule(rule) {
  const newRule = { id: `rule-${Date.now()}`, enabled: true, channels: ['browser'], ...rule };
  _rules.push(newRule);
  return newRule;
}

function removeRule(id) {
  const idx = _rules.findIndex(r => r.id === id);
  if (idx === -1) return false;
  _rules.splice(idx, 1);
  return true;
}

function getConfig() { return _webhookConfig; }

function updateConfig(updates) { Object.assign(_webhookConfig, updates); }

// ── Alert History ─────────────────────────────────────────────────────────────

function getHistory() { return _history; }

function markRead(id) {
  const alert = _history.find(a => a.id === id);
  if (alert) alert.read = true;
  return !!alert;
}

function markAllRead() { _history.forEach(a => { a.read = true; }); }

function getUnreadCount() { return _history.filter(a => !a.read).length; }

// ── Rule Evaluation ───────────────────────────────────────────────────────────

function evaluateAndFire(scan) {
  if (!scan || scan.status !== 'complete') return;

  const enabledRules = _rules.filter(r => r.enabled);

  for (const rule of enabledRules) {
    let triggered = false;
    let triggerDetail = '';
    let topFinding = null;

    switch (rule.trigger) {
      case 'severity': {
        const matches = scan.findings.filter(f => f.severity === rule.value);
        triggered = matches.length > 0;
        topFinding = matches[0] || null;
        triggerDetail = `${matches.length} ${rule.value} finding(s)`;
        break;
      }
      case 'risk_score': {
        triggered = (scan.riskScore?.score || 0) >= Number(rule.value);
        triggerDetail = `Risk score: ${scan.riskScore?.score} (threshold: ${rule.value})`;
        break;
      }
      case 'scan_complete': {
        triggered = true;
        triggerDetail = `Scan finished — Grade ${scan.riskScore?.grade || '?'}`;
        break;
      }
      case 'attack_type': {
        const wapiti = scan.modules?.wapitiscan?.data?.summary || {};
        if (rule.value === 'sqli') { triggered = (wapiti.sqli || 0) > 0; triggerDetail = `SQLi found`; }
        if (rule.value === 'xss')  { triggered = (wapiti.xss  || 0) > 0; triggerDetail = `XSS found`;  }
        if (rule.value === 'cmdi') { triggered = (wapiti.cmdi || 0) > 0; triggerDetail = `CMDi found`; }
        if (rule.value === 'lfi')  { triggered = (wapiti.lfi  || 0) > 0; triggerDetail = `LFI found`;  }
        topFinding = scan.findings.find(f => f.module === 'wapitiscan') || null;
        break;
      }
      case 'open_port': {
        const dangerous = scan.modules?.portScan?.data?.exposedDangerousPorts || [];
        triggered = dangerous.length > 0;
        triggerDetail = `${dangerous.length} dangerous port(s): ${dangerous.map(p=>p.port).join(', ')}`;
        break;
      }
    }

    if (triggered) {
      const alert = {
        id: `alert-${Date.now()}-${Math.random().toString(36).slice(2,6)}`,
        ruleId: rule.id,
        ruleName: rule.name,
        domain: scan.domain,
        scanId: scan.id,
        riskScore: scan.riskScore?.score || 0,
        riskGrade: scan.riskScore?.grade || '?',
        trigger: rule.trigger,
        triggerDetail,
        finding: topFinding ? { title: topFinding.title, severity: topFinding.severity, remediation: topFinding.remediation } : null,
        channels: rule.channels,
        timestamp: new Date().toISOString(),
        read: false,
      };

      _history.unshift(alert);
      if (_history.length > 200) _history.splice(200);

      dispatch(alert);
    }
  }
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

function dispatch(alert) {
  const channels = alert.channels || [];

  // Browser push via WebSocket
  if (channels.includes('browser') && _broadcastAll) {
    _broadcastAll({ event: 'alert_fired', alert });
  }

  // Webhook
  if (channels.includes('webhook') && _webhookConfig.url) {
    sendPost(_webhookConfig.url, buildPayload(alert)).catch(e =>
      console.error('[AlertEngine] Webhook error:', e.message));
  }

  // Slack
  if (channels.includes('slack') && _webhookConfig.slack) {
    const slackMsg = {
      text: `🚨 *ReconScan Alert — ${alert.ruleName}*`,
      attachments: [{
        color: alert.riskScore >= 70 ? 'danger' : alert.riskScore >= 40 ? 'warning' : 'good',
        fields: [
          { title: 'Domain',       value: alert.domain,          short: true },
          { title: 'Risk Score',   value: `${alert.riskScore} (${alert.riskGrade})`, short: true },
          { title: 'Trigger',      value: alert.triggerDetail,   short: false },
          ...(alert.finding ? [{ title: 'Finding', value: alert.finding.title, short: false }] : []),
        ],
        footer: `ReconScan • ${new Date(alert.timestamp).toLocaleString()}`,
      }],
    };
    sendPost(_webhookConfig.slack, slackMsg).catch(e =>
      console.error('[AlertEngine] Slack error:', e.message));
  }

  // Discord
  if (channels.includes('discord') && _webhookConfig.discord) {
    const color = alert.riskScore >= 70 ? 0xe11d48 : alert.riskScore >= 40 ? 0xd97706 : 0x22c55e;
    const discordMsg = {
      username: 'ReconScan',
      embeds: [{
        title: `🚨 Alert: ${alert.ruleName}`,
        color,
        fields: [
          { name: 'Domain',     value: alert.domain,        inline: true },
          { name: 'Risk Score', value: `${alert.riskScore} — Grade ${alert.riskGrade}`, inline: true },
          { name: 'Trigger',    value: alert.triggerDetail, inline: false },
          ...(alert.finding ? [{ name: 'Top Finding', value: alert.finding.title, inline: false }] : []),
        ],
        timestamp: alert.timestamp,
        footer: { text: 'ReconScan Security Platform' },
      }],
    };
    sendPost(_webhookConfig.discord, discordMsg).catch(e =>
      console.error('[AlertEngine] Discord error:', e.message));
  }

  // Email (optional — requires nodemailer)
  if (channels.includes('email') && _webhookConfig.email?.host && _webhookConfig.email?.to) {
    sendEmail(alert).catch(e => console.error('[AlertEngine] Email error:', e.message));
  }
}

// ── Test Alert ────────────────────────────────────────────────────────────────

function fireTestAlert() {
  const test = {
    id: `alert-test-${Date.now()}`,
    ruleId: 'test',
    ruleName: 'Test Alert',
    domain: 'test.example.com',
    scanId: 'test-scan',
    riskScore: 85,
    riskGrade: 'F',
    trigger: 'test',
    triggerDetail: 'This is a test alert from ReconScan',
    finding: { title: 'Test Finding — SQL Injection', severity: 'critical', remediation: 'This is a test.' },
    channels: ['browser', 'webhook', 'slack', 'discord'],
    timestamp: new Date().toISOString(),
    read: false,
  };
  _history.unshift(test);
  dispatch(test);
  return test;
}

// ── HTTP Helpers ──────────────────────────────────────────────────────────────

function buildPayload(alert) {
  return {
    alert: alert.ruleName,
    domain: alert.domain,
    scanId: alert.scanId,
    riskScore: alert.riskScore,
    riskGrade: alert.riskGrade,
    trigger: alert.trigger,
    triggerDetail: alert.triggerDetail,
    finding: alert.finding,
    timestamp: alert.timestamp,
  };
}

function sendPost(url, body) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const parsedUrl = new URL(url);
    const lib = parsedUrl.protocol === 'https:' ? https : http;
    const opts = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
    };
    const req = lib.request(opts, res => { resolve(res.statusCode); });
    req.on('error', reject);
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('timeout')); });
    req.write(payload);
    req.end();
  });
}

async function sendEmail(alert) {
  let nodemailer;
  try { nodemailer = require('nodemailer'); } catch (_) {
    console.warn('[AlertEngine] nodemailer not installed — email alerts disabled. Run: npm install nodemailer');
    return;
  }
  const cfg = _webhookConfig.email;
  const transporter = nodemailer.createTransport({ host: cfg.host, port: cfg.port, auth: { user: cfg.user, pass: cfg.pass } });
  await transporter.sendMail({
    from: cfg.user,
    to: cfg.to,
    subject: `🚨 ReconScan Alert: ${alert.ruleName} — ${alert.domain}`,
    text: `Alert: ${alert.ruleName}\nDomain: ${alert.domain}\nRisk Score: ${alert.riskScore} (${alert.riskGrade})\nTrigger: ${alert.triggerDetail}\n${alert.finding ? `Finding: ${alert.finding.title}` : ''}\nTime: ${alert.timestamp}`,
    html: `<h2>🚨 ReconScan Alert</h2><p><b>Rule:</b> ${alert.ruleName}</p><p><b>Domain:</b> ${alert.domain}</p><p><b>Risk Score:</b> ${alert.riskScore} — Grade ${alert.riskGrade}</p><p><b>Trigger:</b> ${alert.triggerDetail}</p>${alert.finding ? `<p><b>Finding:</b> ${alert.finding.title}</p>` : ''}<hr><small>ReconScan Security Platform</small>`,
  });
}

module.exports = { init, getRules, updateRule, addRule, removeRule, getConfig, updateConfig, getHistory, markRead, markAllRead, getUnreadCount, evaluateAndFire, fireTestAlert };
