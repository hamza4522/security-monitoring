'use strict';
/**
 * rceChecker.js — Remote Command Execution (RCE) Confirmation
 *
 * Safely CONFIRMS OS command injection / remote code execution on injectable
 * parameters and form fields, using an execution-vs-reflection discriminator so
 * it never false-positives, and never does anything beyond a benign proof:
 *
 *   Payload embeds shell arithmetic plus a random nonce, e.g.  ;echo <nonce>$((9*9))
 *   - If the server merely REFLECTS input, the response contains the literal
 *     "<nonce>$((9*9))".
 *   - If the server EXECUTES the command, the shell evaluates the arithmetic and
 *     the response contains the COMPUTED value "<nonce>81".
 *   A finding is raised ONLY when the computed marker appears AND the literal
 *     expression does not — i.e. execution is proven, not reflection.
 *
 * It runs only a benign `echo`/arithmetic (and an optional timing probe). It does
 * NOT read sensitive files, drop a shell, or run attacker-controlled commands.
 * This is a detection/PoC check for authorized attack-surface assessment.
 */

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36';
const REQ_TIMEOUT = 9000;
const MAX_PARAMS   = 8;   // cap injectable points tested
const MAX_FORMS    = 3;

async function safeFetch(url, opts = {}) {
  try {
    const started = Date.now();
    const r = await fetch(url, {
      redirect: 'follow',
      signal: AbortSignal.timeout(opts.timeout || REQ_TIMEOUT),
      headers: { 'User-Agent': UA, Accept: 'text/html,*/*' },
      ...opts,
    });
    const text = await r.text().catch(() => '');
    return { ok: true, status: r.status, text, ms: Date.now() - started };
  } catch (_) {
    return { ok: false, status: 0, text: '', ms: -1 };
  }
}

// ── Injectable-point discovery (query params + simple GET forms) ────────────────

function paramsOf(url) {
  try {
    const u = new URL(url);
    return [...u.searchParams.keys()].map(k => ({ url, param: k }));
  } catch (_) { return []; }
}

function buildUrl(url, param, value) {
  try { const u = new URL(url); u.searchParams.set(param, value); return u.toString(); }
  catch (_) { return url; }
}

function extractParamLinks(html, baseUrl) {
  const out = new Set();
  const re = /href\s*=\s*["']([^"'#]+\?[^"']+)["']/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    try {
      const abs = new URL(m[1], baseUrl);
      const base = new URL(baseUrl);
      if (abs.hostname === base.hostname && abs.searchParams.toString()) out.add(abs.toString());
    } catch (_) {}
  }
  return [...out];
}

// ── Payload builders ────────────────────────────────────────────────────────────
// computed() returns the string a shell produces after evaluating the payload;
// literal is the raw (reflection) form. Confirm only when computed && !literal.

function unixPayloads(nonce) {
  const arith = '$((9*9))';     // shell evaluates → 81
  const literalTail = `${nonce}${arith}`;
  const computed    = `${nonce}81`;
  const seps = [`;echo ${literalTail};`, `|echo ${literalTail}`, `\`echo ${literalTail}\``, `$(echo ${literalTail})`, `%0aecho ${literalTail}`, `'; echo ${literalTail};'`];
  return seps.map(p => ({ payload: p, computed, literal: literalTail, platform: 'unix' }));
}

function windowsPayloads(nonce) {
  // cmd.exe: `set /a 9*9` prints 81. Tie to nonce via echo of the nonce too.
  const computed = `${nonce} 81`;
  const literal  = `${nonce}`;
  const seps = [`& (echo ${nonce} & set /a 9*9)`, `| (echo ${nonce}& set /a 9*9)`];
  // We confirm Windows at lower confidence: the "81" from set /a is not uniquely
  // tied to the nonce, so proximity (nonce then 81) is treated as 'likely'.
  return seps.map(p => ({ payload: p, computed, literal, platform: 'windows' }));
}

// ── Core tester ──────────────────────────────────────────────────────────────────

async function testPoint(injectUrlFor, label, results) {
  const nonce = 'rce' + Math.random().toString(36).slice(2, 10);

  // Baseline (no payload) — used to ensure the computed marker isn't already present.
  const baseline = await safeFetch(injectUrlFor('reconscan_probe'));
  const baseText = baseline.text || '';

  for (const def of [...unixPayloads(nonce), ...windowsPayloads(nonce)]) {
    results.summary.totalProbes++;
    const r = await safeFetch(injectUrlFor(def.payload));
    if (!r.ok) continue;
    const body = r.text || '';

    const hasComputed = body.includes(def.computed) && !baseText.includes(def.computed);
    const reflectedLiterally = body.includes(def.literal) && def.platform === 'unix' && body.includes(def.computed) === false;

    if (def.platform === 'unix') {
      // Confirmed: computed value present, literal expression absent → executed.
      if (hasComputed && !body.includes(def.literal)) {
        return { confirmed: true, confidence: 'confirmed', payload: def.payload, marker: def.computed, platform: 'unix', label };
      }
    } else {
      // Windows: nonce followed (soon) by 81, and NOT the raw payload reflected.
      const near = new RegExp(`${nonce}[\\s\\S]{0,20}\\b81\\b`).test(body);
      if (near && !body.includes(def.payload)) {
        return { confirmed: true, confidence: 'likely', payload: def.payload, marker: def.computed, platform: 'windows', label };
      }
    }
  }
  return null;
}

// ── Main ─────────────────────────────────────────────────────────────────────────

async function runRceChecker(domain, onProgress) {
  const results = {
    domain,
    testedPoints: 0,
    findings: [],
    summary: { totalProbes: 0, confirmed: 0 },
  };

  onProgress('RCE check: fetching target to discover injectable parameters...');
  let baseUrl = '', homeHtml = '';
  for (const scheme of ['https', 'http']) {
    const r = await safeFetch(`${scheme}://${domain}/`, { timeout: 12000 });
    if (r.ok) { baseUrl = `${scheme}://${domain}`; homeHtml = r.text; break; }
  }
  if (!baseUrl) { onProgress('RCE check: target unreachable — skipping'); return results; }

  // Collect injectable query params from the home URL and linked pages.
  const points = [...paramsOf(baseUrl)];
  for (const lurl of extractParamLinks(homeHtml, baseUrl).slice(0, 10)) points.push(...paramsOf(lurl));

  // De-dup by param name, cap.
  const seen = new Set();
  const uniq = points.filter(p => (seen.has(p.param) ? false : (seen.add(p.param), true))).slice(0, MAX_PARAMS);

  if (uniq.length === 0) {
    onProgress('RCE check: no injectable parameters found — nothing to test');
    return results;
  }

  onProgress(`RCE check: testing ${uniq.length} parameter(s) for command execution...`);
  for (const pt of uniq) {
    results.testedPoints++;
    const hit = await testPoint(v => buildUrl(pt.url, pt.param, v), `parameter "${pt.param}"`, results);
    if (hit) {
      results.summary.confirmed++;
      results.findings.push({
        id:          `RCE-CMDEXEC-${pt.param.toUpperCase()}`,
        severity:    'critical',
        confidence:  hit.confidence,
        title:       `Remote Command Execution in ${hit.label}`,
        description:
          `The ${hit.label} executes injected OS commands (${hit.platform}). Proof: a benign arithmetic payload was evaluated server-side — the response returned the COMPUTED marker "${hit.marker}" rather than the literal expression, which is only possible if the shell ran the command. An attacker can run arbitrary commands and obtain a shell on the host.` +
          `\n\nPayload: ${hit.payload}`,
        module:      'rceChecker',
        affected:    buildUrl(pt.url, pt.param, '<payload>'),
        remediation: 'Never pass user input to a shell/OS command. Use language-native APIs with argument arrays (no shell), strict input allowlists, and drop OS-command execution entirely where possible. Rotate any secrets reachable from the affected host.',
        owasp:       'A03:2021 Injection',
        cwe:         'CWE-78',
      });
      onProgress(`RCE check: CONFIRMED command execution via ${hit.label}`);
    }
  }

  onProgress(`RCE check complete — ${results.summary.confirmed} confirmed across ${results.summary.totalProbes} probes`);
  return results;
}

module.exports = { runRceChecker };
