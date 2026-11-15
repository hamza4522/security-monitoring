'use strict';
/**
 * gitExposureScanner.js — Exposed .git Directory Detector (with proof-of-impact)
 *
 * Detects a publicly exposed/dumpable Git repository (the classic "git-dumper"
 * exposure) and PROVES exploitability with bounded evidence — WITHOUT performing
 * a full recursive repository exfiltration.
 *
 * What it does (bounded, read-only, a handful of requests):
 *   1. Confirms /.git/ is a real, dumpable repo (not a soft-404) by validating
 *      the format of /.git/HEAD, /.git/config, and the /.git/index magic bytes.
 *   2. Extracts evidence an auditor needs: remote URL(s) from config, commit
 *      history + author identities from logs/HEAD, and a sample of tracked file
 *      paths parsed from the index (proving the file tree is recoverable).
 *   3. Flags related VCS/metadata exposures (.svn, .hg, .bzr).
 *
 * It deliberately does NOT download every object/pack to rebuild the working
 * tree — detection + proof is enough to make the finding actionable, and mass
 * exfiltration of a third-party repo is out of scope for an attack-surface scan.
 */

const UA = 'Mozilla/5.0 (compatible; ReconScan/2.0; SecurityResearch)';
const REQ_TIMEOUT = 7000;
const MAX_EVIDENCE_BYTES = 256 * 1024; // cap any single file we read

// ── Fetch helper ────────────────────────────────────────────────────────────────

async function fetchRaw(url, { asBuffer = false } = {}) {
  try {
    const r = await fetch(url, {
      redirect: 'manual',
      signal: AbortSignal.timeout(REQ_TIMEOUT),
      headers: { 'User-Agent': UA, Accept: '*/*' },
    });
    if (asBuffer) {
      const ab = await r.arrayBuffer();
      const buf = Buffer.from(ab).subarray(0, MAX_EVIDENCE_BYTES);
      return { status: r.status, buf, headers: Object.fromEntries(r.headers.entries()) };
    }
    const text = (await r.text().catch(() => '')).slice(0, MAX_EVIDENCE_BYTES);
    return { status: r.status, text, headers: Object.fromEntries(r.headers.entries()) };
  } catch (_) {
    return { status: 0, text: '', buf: Buffer.alloc(0), headers: {} };
  }
}

// ── Validators (distinguish a real .git from a soft-404 / catch-all page) ────────

const HEAD_RE = /^(ref:\s+refs\/|[0-9a-f]{40}\b)/m;

function isValidGitHead(text) {
  return HEAD_RE.test((text || '').trim());
}

function isValidGitConfig(text) {
  return /\[core\]/i.test(text || '') && /repositoryformatversion\s*=|\bbare\s*=|\bfilemode\s*=/i.test(text || '');
}

function isValidGitIndex(buf) {
  // Git index files begin with the signature "DIRC" (0x44 49 52 43).
  return buf && buf.length >= 12 && buf.toString('ascii', 0, 4) === 'DIRC';
}

// ── Lightweight .git/index parser (extract a sample of tracked file paths) ──────
/**
 * Parse the Git index (version 2/3/4) just enough to recover tracked file paths.
 * Returns up to `limit` path strings. Best-effort: stops on anything unexpected.
 */
function parseGitIndexPaths(buf, limit = 25) {
  const paths = [];
  try {
    if (!isValidGitIndex(buf)) return paths;
    const version = buf.readUInt32BE(4);
    const entryCount = buf.readUInt32BE(8);
    if (version < 2 || version > 4 || entryCount > 100000) return paths;

    let off = 12;
    for (let i = 0; i < entryCount && paths.length < limit; i++) {
      // Fixed 62-byte entry header, then a NUL-terminated path, then 1-8 bytes
      // of padding so each entry is a multiple of 8 bytes (v2/v3).
      if (off + 62 > buf.length) break;
      const pathStart = off + 62;
      let end = pathStart;
      while (end < buf.length && buf[end] !== 0x00) end++;
      const path = buf.toString('utf8', pathStart, end);
      if (path && /^[\x20-\x7e]+$/.test(path)) paths.push(path);

      if (version === 4) {
        // v4 uses prefix-compression + varints — too fragile to walk reliably,
        // so stop after what we have; the sample already proves the exposure.
        break;
      }
      // Advance: round the entry length up to the next multiple of 8.
      const entryLen = 62 + (end - pathStart) + 1;
      off += Math.ceil(entryLen / 8) * 8;
    }
  } catch (_) { /* best-effort */ }
  return paths;
}

// ── Evidence extractors ─────────────────────────────────────────────────────────

function extractRemotes(configText) {
  const remotes = [];
  const re = /url\s*=\s*(.+)/gi;
  let m;
  while ((m = re.exec(configText)) !== null) {
    const url = m[1].trim();
    if (url) remotes.push(url);
  }
  return [...new Set(remotes)];
}

function extractLogIdentities(logText) {
  // .git/logs/HEAD lines: <old> <new> <Name> <email> <ts> <tz>\t<message>
  const commits = [];
  const emails = new Set();
  for (const line of (logText || '').split('\n')) {
    const m = line.match(/^([0-9a-f]{40})\s+([0-9a-f]{40})\s+(.+?)\s+<([^>]+)>/);
    if (m) {
      emails.add(m[4]);
      commits.push({ to: m[2].slice(0, 10), author: m[3], email: m[4] });
    }
  }
  return { commits: commits.slice(0, 10), emails: [...emails].slice(0, 10) };
}

// ── Main ─────────────────────────────────────────────────────────────────────────

async function runGitExposureScanner(domain, onProgress) {
  const results = {
    domain,
    exposed: false,
    evidence: {},
    findings: [],
    summary: { gitExposed: false, remotes: 0, emails: 0, sampleFiles: 0 },
  };

  // Resolve a working base URL.
  onProgress('Git exposure: probing for an exposed .git directory...');
  let baseUrl = '';
  for (const scheme of ['https', 'http']) {
    const r = await fetchRaw(`${scheme}://${domain}/`);
    if (r.status > 0) { baseUrl = `${scheme}://${domain}`; break; }
  }
  if (!baseUrl) { onProgress('Git exposure: target unreachable — skipping'); return results; }

  // Soft-404 baseline: if a random path under /.git/ returns 200, we must rely on
  // strict content validation (which we do) rather than status codes alone.
  const rnd = await fetchRaw(`${baseUrl}/.git/nope-${Date.now()}`);
  const soft404 = rnd.status === 200;

  // ── Core confirmation: HEAD + config + index ────────────────────────────────
  const head   = await fetchRaw(`${baseUrl}/.git/HEAD`);
  const config = await fetchRaw(`${baseUrl}/.git/config`);
  const index  = await fetchRaw(`${baseUrl}/.git/index`, { asBuffer: true });

  const headOk   = head.status === 200 && isValidGitHead(head.text);
  const configOk = config.status === 200 && isValidGitConfig(config.text);
  const indexOk  = index.status === 200 && isValidGitIndex(index.buf);

  // Require at least one STRONGLY-validated artifact. Content validation (not
  // status) is what rules out soft-404 catch-all pages.
  if (!headOk && !configOk && !indexOk) {
    onProgress('Git exposure: no exposed .git directory detected');
    // Still run the related-VCS check below before returning.
    await checkOtherVCS(baseUrl, soft404, results, onProgress);
    return results;
  }

  results.exposed = true;
  results.summary.gitExposed = true;

  // ── Gather bounded evidence ─────────────────────────────────────────────────
  onProgress('Git exposure: confirmed — collecting proof-of-impact evidence...');
  const remotes = configOk ? extractRemotes(config.text) : [];

  const logsHead = await fetchRaw(`${baseUrl}/.git/logs/HEAD`);
  const identities = logsHead.status === 200 ? extractLogIdentities(logsHead.text) : { commits: [], emails: [] };

  const sampleFiles = indexOk ? parseGitIndexPaths(index.buf) : [];

  results.evidence = {
    confirmedBy:   [headOk && 'HEAD', configOk && 'config', indexOk && 'index'].filter(Boolean),
    head:          headOk ? head.text.trim().slice(0, 120) : null,
    remotes,
    commits:       identities.commits,
    authorEmails:  identities.emails,
    sampleFiles,
    indexAccessible: indexOk,
  };
  results.summary.remotes     = remotes.length;
  results.summary.emails      = identities.emails.length;
  results.summary.sampleFiles = sampleFiles.length;

  // ── Build the finding ───────────────────────────────────────────────────────
  const evLines = [];
  if (remotes.length)              evLines.push(`Remote(s): ${remotes.join(', ')}`);
  if (identities.emails.length)    evLines.push(`Committer email(s): ${identities.emails.join(', ')}`);
  if (sampleFiles.length)          evLines.push(`Recoverable files (sample): ${sampleFiles.slice(0, 10).join(', ')}${sampleFiles.length > 10 ? ', …' : ''}`);

  results.findings.push({
    id:          'GIT-EXPOSED-REPO',
    severity:    'critical',
    confidence:  'confirmed',
    title:       'Exposed Git Repository (.git) — Full Source Recoverable',
    description:
      `A publicly accessible Git repository was confirmed at ${baseUrl}/.git/ ` +
      `(validated via: ${results.evidence.confirmedBy.join(', ')}). ` +
      `Because ${indexOk ? 'the index and ' : ''}repository metadata are served directly, an attacker can reconstruct the ENTIRE source code and full commit history using a tool like git-dumper — frequently exposing hardcoded credentials, API keys, internal hostnames, and private business logic.` +
      (evLines.length ? `\n\nEvidence:\n- ${evLines.join('\n- ')}` : ''),
    module:      'gitExposureScanner',
    affected:    `${baseUrl}/.git/`,
    remediation:
      'Block all access to the .git directory at the web server (e.g. Apache: RedirectMatch 404 /\\.git; Nginx: location ~ /\\.git { deny all; return 404; }). Never deploy the .git directory to production — use a clean export/CI artifact. ROTATE any credentials that were ever committed, since history is already exposed.',
    owasp:       'A05:2021 Security Misconfiguration',
    cves:        [],
  });

  // Also surface committed secrets hint if remotes contain embedded creds.
  for (const r of remotes) {
    if (/\/\/[^/@\s]+:[^/@\s]+@/.test(r)) {
      results.findings.push({
        id:          'GIT-REMOTE-CREDENTIALS',
        severity:    'critical',
        confidence:  'confirmed',
        title:       'Credentials Embedded in Exposed Git Remote URL',
        description: `The exposed .git/config contains a remote URL with embedded credentials: ${r.replace(/\/\/([^:]+):[^@]+@/, '//$1:***@')}. These credentials are directly readable by anyone.`,
        module:      'gitExposureScanner',
        affected:    `${baseUrl}/.git/config`,
        remediation: 'Rotate the exposed credentials immediately. Remove credentials from remote URLs; use credential helpers or deploy keys instead.',
        owasp:       'A07:2021 Identification and Authentication Failures',
      });
      break;
    }
  }

  await checkOtherVCS(baseUrl, soft404, results, onProgress);

  onProgress(`Git exposure: CONFIRMED — ${results.findings.length} finding(s), ${sampleFiles.length} recoverable file(s) sampled`);
  return results;
}

// ── Related VCS / metadata directory exposure (.svn / .hg / .bzr) ───────────────

async function checkOtherVCS(baseUrl, soft404, results, onProgress) {
  const checks = [
    // Old-format .svn/entries begins with the working-copy format number on its
    // own line (e.g. "10\n"/"12\n"). Require that exact shape — do NOT match the
    // words "entries"/"dir", which a soft-404 page echoing the URL would contain.
    { path: '/.svn/entries',      name: 'Subversion (.svn)',  verify: t => /^\d{1,3}\r?\n/.test(t) && /svn:|has-props|dir\r?\n|file\r?\n/.test(t) },
    { path: '/.svn/wc.db',        name: 'Subversion wc.db',   verify: t => /^SQLite format 3\x00/.test(t) },
    { path: '/.hg/requires',      name: 'Mercurial (.hg)',    verify: t => /^(revlogv1|store|dotencode|fncache|generaldelta|sparserevlog)\b/m.test(t) },
    { path: '/.bzr/branch-format',name: 'Bazaar (.bzr)',      verify: t => /^Bazaar(-NG)? (branch|meta directory) format/i.test(t) },
  ];
  const looksLikeHTML = (t) => /<\s*(?:!doctype|html|head|body|script|title)\b/i.test((t || '').slice(0, 1024));
  for (const c of checks) {
    const r = await fetchRaw(`${baseUrl}${c.path}`);
    if (r.status !== 200) continue;
    // VCS metadata is never an HTML page — reject soft-404 catch-all responses.
    if (looksLikeHTML(r.text)) continue;
    // Require positive, strict content validation — never trust a 200 alone.
    if (!c.verify(r.text || '')) continue;
    results.findings.push({
      id:          `VCS-EXPOSED-${c.name.replace(/[^A-Z0-9]/gi, '-').toUpperCase()}`,
      severity:    'high',
      confidence:  'confirmed',
      title:       `Exposed Version Control Metadata: ${c.name}`,
      description: `${c.name} version-control metadata is publicly accessible at ${baseUrl}${c.path}. This can expose source code and repository structure.`,
      module:      'gitExposureScanner',
      affected:    `${baseUrl}${c.path}`,
      remediation: `Block access to the version-control directory at the web server and remove it from the deployed webroot.`,
      owasp:       'A05:2021 Security Misconfiguration',
    });
  }
}

module.exports = { runGitExposureScanner };
