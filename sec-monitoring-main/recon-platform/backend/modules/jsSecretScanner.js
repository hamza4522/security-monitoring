'use strict';
/**
 * jsSecretScanner.js — JavaScript File Secret & Credential Detector
 *
 * Crawls JS files linked from the target page and scans for:
 *   - AWS / GCP / Azure / Firebase credentials
 *   - Stripe, Twilio, SendGrid, Mailgun, Slack API keys
 *   - GitHub / GitLab / npm tokens
 *   - Private keys (RSA, EC, PGP)
 *   - JWT secrets, hardcoded passwords, connection strings
 *   - High-entropy strings (Shannon entropy analysis)
 *
 * Inspired by: TruffleHog, SecretFinder, GitLeaks regex patterns
 */

const UA = 'Mozilla/5.0 (compatible; SecurityScanner/2.0)';
const MAX_JS_FILES   = 20;   // max JS files to scan
const MAX_JS_SIZE    = 500_000; // bytes — skip huge bundles beyond this
const ENTROPY_THRESH = 4.5;  // Shannon entropy threshold for high-entropy strings
const HE_MIN_LEN     = 20;   // minimum string length for entropy check
const HE_MAX_LEN     = 80;   // maximum string length for entropy check

// ── Secret Patterns ───────────────────────────────────────────────────────────
// Each: { id, name, severity, regex, description, remediation }

const SECRET_PATTERNS = [
  // ── Cloud Providers ───────────────────────────────────────────────────────
  {
    id: 'AWS-ACCESS-KEY',
    name: 'AWS Access Key ID',
    severity: 'critical',
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    desc: 'AWS Access Key ID found in JavaScript. This grants access to AWS services.',
    fix: 'Immediately rotate the key in AWS IAM. Move secrets to AWS Secrets Manager or environment variables.',
  },
  {
    id: 'AWS-SECRET-KEY',
    name: 'AWS Secret Access Key',
    severity: 'critical',
    regex: /(?:aws[_\-\s]?secret|aws[_\-\s]?access[_\-\s]?key[_\-\s]?secret|secretaccesskey)['":\s=]+([A-Za-z0-9/+=]{40})\b/gi,
    desc: 'AWS Secret Access Key found in JavaScript. Combined with the access key ID, grants full API access.',
    fix: 'Immediately rotate in AWS IAM. Use IAM roles or Secrets Manager instead.',
  },
  {
    id: 'GCP-API-KEY',
    name: 'Google Cloud / GCP API Key',
    severity: 'critical',
    regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
    desc: 'Google Cloud API key detected. May grant access to Google APIs including Maps, Translation, Firebase, etc.',
    fix: 'Restrict the API key to specific APIs and HTTP referrers in Google Cloud Console. Rotate immediately.',
  },
  {
    id: 'FIREBASE-CONFIG',
    name: 'Firebase Configuration',
    severity: 'high',
    regex: /firebase[_\-\s]?config|firebaseConfig\s*=\s*\{[^}]*apiKey\s*:\s*["']([^"']+)/gi,
    desc: 'Firebase configuration with API key found. May expose your Firebase project.',
    fix: 'Add Firebase Security Rules. Restrict key to authorized domains only.',
  },
  {
    id: 'AZURE-CLIENT-SECRET',
    name: 'Azure Client Secret',
    severity: 'critical',
    regex: /(?:azure[_\-\s]?client[_\-\s]?secret|clientSecret|AZURE_CLIENT_SECRET)['":\s=]+([A-Za-z0-9~._\-]{30,50})/gi,
    desc: 'Azure Active Directory client secret found.',
    fix: 'Rotate in Azure AD. Use Managed Identities or Key Vault references.',
  },
  // ── Payment / Communication APIs ──────────────────────────────────────────
  {
    id: 'STRIPE-SECRET-KEY',
    name: 'Stripe Secret API Key',
    severity: 'critical',
    regex: /\b(sk_live_[0-9a-zA-Z]{24,})\b/g,
    desc: 'Stripe live secret key found in client-side JavaScript. Attackers can make charges and access your customer data.',
    fix: 'Immediately revoke in Stripe Dashboard. Never use secret keys client-side — use publishable keys only.',
  },
  {
    id: 'STRIPE-PUB-KEY',
    name: 'Stripe Publishable Key',
    severity: 'low',
    regex: /\b(pk_live_[0-9a-zA-Z]{24,})\b/g,
    desc: 'Stripe publishable key found (intended for client-side use, but confirms Stripe integration).',
    fix: 'Publishable keys are designed for client-side but verify billing integration is secure.',
  },
  {
    id: 'STRIPE-TEST-KEY',
    name: 'Stripe Test Key',
    severity: 'low',
    regex: /\b(sk_test_[0-9a-zA-Z]{24,}|pk_test_[0-9a-zA-Z]{24,})\b/g,
    desc: 'Stripe test key found. While not production, confirms payment integration and key exposure patterns.',
    fix: 'Keep test keys out of client-side code. Ensure production keys are rotated.',
  },
  {
    id: 'TWILIO-TOKEN',
    name: 'Twilio API Key / Auth Token',
    severity: 'critical',
    regex: /(?:twilio[_\-\s]?auth[_\-\s]?token|TWILIO_AUTH_TOKEN)['":\s=]+([A-Fa-f0-9]{32})\b/gi,
    desc: 'Twilio Auth Token found. Grants full access to your Twilio account (send SMS, calls, view data).',
    fix: 'Revoke in Twilio Console. Move to server-side only.',
  },
  {
    id: 'SENDGRID-KEY',
    name: 'SendGrid API Key',
    severity: 'high',
    regex: /\b(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})\b/g,
    desc: 'SendGrid API key found. Allows sending email from your domain.',
    fix: 'Revoke in SendGrid. Move to server-side. Create a restricted key with minimal permissions.',
  },
  {
    id: 'MAILGUN-KEY',
    name: 'Mailgun API Key',
    severity: 'high',
    regex: /\b(key-[0-9a-zA-Z]{32})\b/g,
    desc: 'Mailgun API key found in client-side code.',
    fix: 'Revoke in Mailgun Dashboard. All email operations should be server-side.',
  },
  {
    id: 'SLACK-TOKEN',
    name: 'Slack API Token',
    severity: 'high',
    regex: /\b(xox[baprs]-[0-9A-Za-z\-]{10,80})\b/g,
    desc: 'Slack bot/user token found. May allow reading Slack messages and channel history.',
    fix: 'Revoke in Slack App settings. Use Slack OAuth for user-scoped access.',
  },
  {
    id: 'SLACK-WEBHOOK',
    name: 'Slack Incoming Webhook',
    severity: 'medium',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/g,
    desc: 'Slack Incoming Webhook URL found. Allows anyone to post messages to your Slack channel.',
    fix: 'Revoke the webhook in Slack. Never expose webhooks in client-side code.',
  },
  // ── Version Control ───────────────────────────────────────────────────────
  {
    id: 'GITHUB-TOKEN',
    name: 'GitHub Personal Access Token',
    severity: 'critical',
    regex: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{82})\b/g,
    desc: 'GitHub Personal Access Token found. May grant read/write access to repositories.',
    fix: 'Immediately revoke in GitHub Settings > Developer Settings > Personal Access Tokens.',
  },
  {
    id: 'GITLAB-TOKEN',
    name: 'GitLab Personal Access Token',
    severity: 'critical',
    regex: /\b(glpat-[A-Za-z0-9\-_]{20})\b/g,
    desc: 'GitLab Personal Access Token found.',
    fix: 'Revoke in GitLab User Settings > Access Tokens.',
  },
  {
    id: 'NPM-TOKEN',
    name: 'npm Access Token',
    severity: 'critical',
    regex: /\b(npm_[A-Za-z0-9]{36})\b/g,
    desc: 'npm access token found. May allow publishing malicious packages.',
    fix: 'Revoke in npm account settings. Use .npmrc with CI-scoped tokens instead.',
  },
  // ── Private Keys ──────────────────────────────────────────────────────────
  {
    id: 'PRIVATE-KEY-RSA',
    name: 'RSA Private Key',
    severity: 'critical',
    regex: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g,
    desc: 'RSA/PKCS private key found in JavaScript. This completely compromises any TLS certificate using this key.',
    fix: 'Immediately revoke and reissue certificates. Private keys must never leave the server.',
  },
  {
    id: 'PRIVATE-KEY-EC',
    name: 'EC/OpenSSH Private Key',
    severity: 'critical',
    regex: /-----BEGIN (?:EC|OPENSSH|DSA|PGP) PRIVATE KEY-----/g,
    desc: 'Private key found in JavaScript.',
    fix: 'Revoke immediately. Never include private keys in any client-side code or repository.',
  },
  // ── Database / Connection Strings ─────────────────────────────────────────
  {
    id: 'DB-CONNECTION-STRING',
    name: 'Database Connection String',
    severity: 'critical',
    regex: /(?:mongodb(?:\+srv)?|mysql|postgresql|postgres|redis|sqlserver):\/\/[^/\s"'<>]+:[^@\s"'<>]+@[^/\s"'<>]+/gi,
    desc: 'Database connection string with credentials found in client-side JavaScript.',
    fix: 'Never expose connection strings client-side. Move all DB access to backend APIs.',
  },
  {
    id: 'POSTGRES-URL',
    name: 'PostgreSQL URL with Credentials',
    severity: 'critical',
    regex: /postgres(?:ql)?:\/\/([^:]+):([^@]+)@/gi,
    desc: 'PostgreSQL URL with username/password exposed in JavaScript.',
    fix: 'Remove immediately. Use server-side API endpoints to interact with databases.',
  },
  // ── JWT Secrets ───────────────────────────────────────────────────────────
  {
    id: 'JWT-SECRET',
    name: 'JWT Secret / Signing Key',
    severity: 'critical',
    regex: /(?:jwt[_\-\s]?secret|jwt[_\-\s]?key|JWT_SECRET|signing[_\-\s]?key|SECRET_KEY)['":\s=]+["']([A-Za-z0-9!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]{16,})/gi,
    desc: 'JWT signing secret found in JavaScript. Attackers can forge any JWT token.',
    fix: 'Rotate the JWT secret. JWT secrets must only exist server-side.',
  },
  // ── Other API Keys ────────────────────────────────────────────────────────
  {
    id: 'GOOGLE-MAPS-KEY',
    name: 'Google Maps API Key',
    severity: 'medium',
    regex: /(?:googlemaps|maps\.googleapis\.com)[^"']*[?&]key=([A-Za-z0-9\-_]{39})/gi,
    desc: 'Google Maps API key found. Without restrictions, can be abused for quota theft.',
    fix: 'Add HTTP referrer restrictions in Google Cloud Console.',
  },
  {
    id: 'MAILCHIMP-KEY',
    name: 'Mailchimp API Key',
    severity: 'high',
    regex: /\b([A-Za-z0-9]{32}-us\d{1,2})\b/g,
    desc: 'Mailchimp API key found. Allows access to mailing lists and subscriber data.',
    fix: 'Revoke in Mailchimp Account Settings. Move all email operations to server-side.',
  },
  {
    id: 'TELEGRAM-BOT-TOKEN',
    name: 'Telegram Bot Token',
    severity: 'high',
    regex: /\b(\d{8,10}:[A-Za-z0-9_\-]{35})\b/g,
    desc: 'Telegram Bot API token found. Allows full control of your Telegram bot.',
    fix: 'Revoke via /revoke with BotFather. Keep bot tokens server-side.',
  },
  {
    id: 'GENERIC-SECRET',
    name: 'Generic Secret / Password in Code',
    severity: 'high',
    // Only flag when the value is NOT a common placeholder/example string
    regex: /(?:password|passwd|secret|api_key|apikey|auth_token|access_token|private_key)\s*[:=]\s*["']([^"']{8,60})["']/gi,
    desc: 'Hardcoded credential or secret value found in JavaScript.',
    fix: 'Remove hardcoded credentials. Use environment variables and server-side secret management.',
  },
];

// ── Shannon Entropy ────────────────────────────────────────────────────────────

function shannonEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Strings that look like hex or base64 and are high-entropy
function findHighEntropyStrings(source) {
  const results = [];
  const strRegex = /["'`]([A-Za-z0-9/+=\-_]{20,80})["'`]/g;
  const seen = new Set();
  let m;
  while ((m = strRegex.exec(source)) !== null) {
    const s = m[1];
    if (seen.has(s)) continue;
    seen.add(s);
    // Skip obvious false positives
    if (/^[A-Za-z]+$/.test(s)) continue;        // all letters = probably a word
    if (s.includes('/')) continue;               // file paths, URLs, base64 with slashes
    if (s.includes('http') || s.includes('www') || s.includes('cdn')) continue;
    if (/^[0-9a-f]+$/i.test(s) && s.length < 32) continue; // short hex = likely a color or ID
    if (s.length < HE_MIN_LEN || s.length > HE_MAX_LEN) continue;
    const e = shannonEntropy(s);
    if (e >= ENTROPY_THRESH) {
      results.push({ value: s.slice(0, 40) + (s.length > 40 ? '...' : ''), entropy: e.toFixed(2) });
    }
  }
  return results.slice(0, 10); // cap at 10
}

// ── JS File Crawler ───────────────────────────────────────────────────────────

async function fetchText(url, timeout = 12000) {
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(timeout), headers: { 'User-Agent': UA } });
    if (!r.ok) return null;
    const ct = r.headers.get('content-type') || '';
    if (!ct.includes('javascript') && !ct.includes('text') && !ct.includes('application')) return null;
    const buf = await r.arrayBuffer();
    if (buf.byteLength > MAX_JS_SIZE) return null; // too large
    return new TextDecoder().decode(buf);
  } catch (_) { return null; }
}

function extractJSUrls(html, baseUrl) {
  const urls = new Set();
  const base = new URL(baseUrl);

  // <script src="...">
  const srcRe = /<script[^>]+src=["']([^"']+\.js(?:[?#][^"']*)?)["']/gi;
  let m;
  while ((m = srcRe.exec(html)) !== null) {
    try {
      const url = new URL(m[1], base).href;
      if (url.startsWith('http')) urls.add(url);
    } catch (_) {}
  }

  // Inline script refs like "/static/js/main.abc123.js"
  const pathRe = /["'](\/?(?:static|js|assets|dist|build|public|_next)[^"']*\.js)["']/gi;
  while ((m = pathRe.exec(html)) !== null) {
    try {
      const url = new URL(m[1], base).href;
      if (url.startsWith('http')) urls.add(url);
    } catch (_) {}
  }

  // chunk files referenced in webpack bundles
  const chunkRe = /\/\*\s*webpackChunkName.*?\*\/\s*["']([^"']+)["']/gi;
  while ((m = chunkRe.exec(html)) !== null) {
    try {
      const url = new URL('/static/js/' + m[1] + '.js', base).href;
      urls.add(url);
    } catch (_) {}
  }

  return [...urls].slice(0, MAX_JS_FILES);
}

function scanForSecrets(source, fileUrl) {
  const found = [];
  const seen = new Set();

  // Placeholder/example values to exclude from GENERIC-SECRET matches
  const PLACEHOLDER_VALS = new Set([
    'your-secret', 'your_secret', 'your-api-key', 'your_api_key', 'changeme',
    'password', 'secret', 'example', 'placeholder', 'xxxxxxxx', '********',
    'your-password', 'your_password', 'supersecret', 'mysecret', 'test',
    'abc123', '12345678', 'passw0rd', 'p@ssw0rd', 'enter_key_here',
  ]);

  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0; // reset global regex
    let m;
    while ((m = pattern.regex.exec(source)) !== null) {
      const match = m[1] || m[0];

      // Skip placeholder values for generic secret pattern
      if (pattern.id === 'GENERIC-SECRET' && PLACEHOLDER_VALS.has(match.toLowerCase())) continue;
      // Also skip very short matches for generic secret (likely a test value)
      if (pattern.id === 'GENERIC-SECRET' && match.length < 12) continue;

      const key = `${pattern.id}:${match.slice(0, 20)}`;
      if (seen.has(key)) continue;
      seen.add(key);

      // Mask value for display — show first 8 chars + asterisks
      const masked = match.length > 8 ? match.slice(0, 8) + '•'.repeat(Math.min(8, match.length - 8)) : match;

      // Find line number
      const lineNum = source.substring(0, m.index).split('\n').length;

      found.push({
        patternId:   pattern.id,
        name:        pattern.name,
        severity:    pattern.severity,
        maskedValue: masked,
        lineNumber:  lineNum,
        context:     source.substring(Math.max(0, m.index - 40), m.index + 60).replace(/\s+/g, ' ').trim(),
        fileUrl,
        desc:        pattern.desc,
        fix:         pattern.fix,
      });
    }
  }

  return found;
}

// ── Main Export ───────────────────────────────────────────────────────────────

async function runJSSecretScanner(domain, onProgress) {
  const results = {
    domain,
    scannedFiles: [],
    secrets: [],
    highEntropyStrings: [],
    findings: [],
    summary: { filesScanned: 0, secretsFound: 0, highEntropyHits: 0, totalIssues: 0 },
  };

  const baseUrls = [`https://${domain}`, `http://${domain}`];
  let homeHtml = '';
  let baseUrl  = '';

  onProgress('Fetching homepage to discover JavaScript files...');
  for (const url of baseUrls) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(12000), headers: { 'User-Agent': UA } });
      if (!r.ok && r.status !== 0) continue;
      homeHtml = await r.text();
      baseUrl  = url;
      break;
    } catch (_) {}
  }

  if (!baseUrl) { onProgress('Target unreachable — skipping JS secret scan'); return results; }

  // Discover JS files
  const jsUrls = extractJSUrls(homeHtml, baseUrl);
  // Also add inline script content
  const inlineScripts = [...homeHtml.matchAll(/<script(?![^>]+src)[^>]*>([\s\S]*?)<\/script>/gi)].map(m => m[1]).join('\n');

  onProgress(`Discovered ${jsUrls.length} JavaScript file(s) to scan...`);

  // Scan inline scripts first
  if (inlineScripts.length > 100) {
    const inlineSecrets = scanForSecrets(inlineScripts, baseUrl + ' [inline]');
    const heStrings = findHighEntropyStrings(inlineScripts);
    results.secrets.push(...inlineSecrets);
    results.highEntropyStrings.push(...heStrings.map(h => ({ ...h, source: 'inline' })));
  }

  // Scan each JS file
  const fileScans = jsUrls.map(async (url, i) => {
    const source = await fetchText(url);
    if (!source) return;

    results.scannedFiles.push(url);
    results.summary.filesScanned++;

    const fileSecrets = scanForSecrets(source, url);
    const heStrings   = findHighEntropyStrings(source);

    results.secrets.push(...fileSecrets);
    results.highEntropyStrings.push(...heStrings.map(h => ({ ...h, source: url })));

    if (fileSecrets.length > 0) {
      onProgress(`Found ${fileSecrets.length} secret(s) in ${url.split('/').pop()}`);
    }
  });
  await Promise.allSettled(fileScans);

  // Deduplicate secrets
  const seen = new Set();
  results.secrets = results.secrets.filter(s => {
    const key = `${s.patternId}:${s.maskedValue}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Build findings
  for (const secret of results.secrets) {
    results.findings.push({
      id:          `JSSCAN-${secret.patternId}-${results.findings.length}`,
      severity:    secret.severity,
      title:       `Secret Exposed in JavaScript: ${secret.name}`,
      description: `${secret.desc} Found in: ${secret.fileUrl}\nLine ~${secret.lineNumber}. Masked value: ${secret.maskedValue}`,
      module:      'jsSecretScanner',
      affected:    secret.fileUrl,
      remediation: secret.fix,
      details: {
        patternId:   secret.patternId,
        maskedValue: secret.maskedValue,
        lineNumber:  secret.lineNumber,
        context:     secret.context,
      },
    });
  }

  // High entropy summary finding
  const heUniq = [...new Map(results.highEntropyStrings.map(h => [h.value, h])).values()].slice(0, 5);
  if (heUniq.length >= 3) {
    results.findings.push({
      id:          'JSSCAN-HIGH-ENTROPY',
      severity:    'medium',
      title:       `${heUniq.length} High-Entropy Strings Found in JavaScript`,
      description: `Detected ${heUniq.length} strings with Shannon entropy ≥${ENTROPY_THRESH}, suggesting possible hardcoded keys or tokens. Top samples: ${heUniq.map(h => h.value).join(', ')}`,
      module:      'jsSecretScanner',
      remediation: 'Review flagged strings. Move any secrets to server-side environment variables.',
    });
  }

  results.summary.secretsFound     = results.secrets.length;
  results.summary.highEntropyHits  = heUniq.length;
  results.summary.totalIssues      = results.findings.length;

  onProgress(`JS secret scan complete — ${results.findings.length} issue(s) across ${results.summary.filesScanned} file(s)`);
  return results;
}

module.exports = { runJSSecretScanner };
