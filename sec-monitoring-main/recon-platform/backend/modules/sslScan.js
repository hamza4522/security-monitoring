'use strict';
/**
 * sslScan.js — SSL/TLS Certificate Scanner
 *
 * Scans the main domain AND all discovered subdomains for SSL certificate
 * validity, expiry, issuer, protocol support, and misconfigurations.
 *
 * Uses only Node.js built-in modules (tls, net) — no extra dependencies.
 */

const tls = require('tls');

// ── Main export ───────────────────────────────────────────────────────────────

async function runSSLScan(domain, onProgress, subdomains = []) {
  const results = {
    domain,
    hosts: [],          // per-host SSL results
    summary: {
      total:   0,
      valid:   0,
      expiring: 0,
      expired:  0,
      noSSL:    0,
    },
    findings: [],
  };

  // Deduplicate: main domain + subdomains (max 30 to stay within timeout budget)
  const targets = [...new Set([domain, ...subdomains])].slice(0, 30);
  results.summary.total = targets.length;

  onProgress(`Scanning SSL certificates for ${targets.length} host(s)...`);

  const checks = targets.map(async (host, idx) => {
    try {
      const info = await getCertInfo(host);
      if (!info) {
        results.hosts.push({
          host,
          hasSSL:   false,
          status:   'no_ssl',
          daysLeft: null,
          issuer:   null,
          subject:  null,
          validFrom: null,
          validTo:  null,
          protocol: null,
          san:      [],
          error:    'No SSL / connection refused',
        });
        results.summary.noSSL++;
        return;
      }

      const now = Date.now();
      const daysLeft = Math.floor((new Date(info.validTo) - now) / 86_400_000);
      const expired  = daysLeft < 0;
      const expiring = !expired && daysLeft <= 30;

      const status = expired ? 'expired' : expiring ? 'expiring' : 'valid';

      results.hosts.push({
        host,
        hasSSL:   true,
        status,
        daysLeft,
        issuer:   info.issuer,
        subject:  info.subject,
        validFrom: info.validFrom,
        validTo:  info.validTo,
        protocol: info.protocol,
        san:      info.san || [],
        selfSigned: info.selfSigned,
        error:    null,
      });

      if (expired) {
        results.summary.expired++;
        results.findings.push({
          id:          `SSL-EXPIRED-${host}`,
          severity:    'critical',
          confidence:  'confirmed',
          title:       `SSL Certificate EXPIRED: ${host}`,
          description: `The SSL certificate for ${host} expired ${Math.abs(daysLeft)} day(s) ago (on ${new Date(info.validTo).toLocaleDateString()}). Browsers will show a security warning and block access.`,
          module:      'sslScan',
          affected:    host,
          remediation: 'Renew the SSL/TLS certificate immediately. Use Let\'s Encrypt (certbot) or your CA provider.',
        });
      } else if (expiring) {
        results.summary.expiring++;
        results.findings.push({
          id:          `SSL-EXPIRING-${host}`,
          severity:    daysLeft <= 7 ? 'high' : 'medium',
          confidence:  'confirmed',
          title:       `SSL Certificate Expiring Soon: ${host} (${daysLeft} days)`,
          description: `The SSL certificate for ${host} will expire in ${daysLeft} day(s) on ${new Date(info.validTo).toLocaleDateString()}. Failure to renew will cause browsers to display security warnings.`,
          module:      'sslScan',
          affected:    host,
          remediation: 'Renew the SSL/TLS certificate before it expires. Enable auto-renewal via certbot or your CA dashboard.',
        });
      } else {
        results.summary.valid++;
      }

      // Self-signed certificate
      if (info.selfSigned) {
        results.findings.push({
          id:          `SSL-SELFSIGNED-${host}`,
          severity:    'high',
          confidence:  'confirmed',
          title:       `Self-Signed SSL Certificate: ${host}`,
          description: `The certificate for ${host} is self-signed (issuer = subject). Browsers display "not trusted" warnings to visitors, which erodes user trust and can indicate a misconfiguration.`,
          module:      'sslScan',
          affected:    host,
          remediation: 'Replace the self-signed certificate with one issued by a trusted CA (e.g., Let\'s Encrypt, DigiCert).',
        });
      }

      // ── Supported-protocol enumeration ─────────────────────────────────────
      // Probe each TLS version independently so we detect protocols the server
      // ACCEPTS (not merely the one negotiated by default). This catches servers
      // that still allow TLS 1.0/1.1 even though 1.2/1.3 is preferred.
      const proto = await probeProtocols(host);
      const hostEntry = results.hosts.find(hh => hh.host === host);
      if (hostEntry) hostEntry.supportedProtocols = proto;

      // Flag deprecated TLS ONLY on a clean handshake (proto.supported). We do
      // NOT infer support from post-negotiation errors: a modern OpenSSL client
      // produces the same key-exchange error whether or not the server actually
      // speaks TLS 1.0/1.1, so that signal is unreliable and would false-positive.
      // Trade-off: a legacy-only server whose old cipher this client can't
      // complete may be missed — a deliberate false-negative over a false-positive.
      const weak = proto.supported.filter(p => p === 'TLSv1' || p === 'TLSv1.1');

      if (weak.length > 0) {
        results.findings.push({
          id:          `SSL-WEAKPROTO-${host}`,
          severity:    'high',
          confidence:  'confirmed',
          title:       `Deprecated TLS Protocol Supported: ${host} (${weak.join(', ')})`,
          description: `The server at ${host} completed a handshake over ${weak.join(' and ')}, which ${weak.length > 1 ? 'are' : 'is'} deprecated (RFC 8996) and vulnerable to downgrade and BEAST/POODLE-style attacks. Supported protocols: ${proto.supported.join(', ') || 'none'}.`,
          module:      'sslScan',
          affected:    host,
          remediation: 'Disable TLSv1.0 and TLSv1.1 at the server. Accept only TLSv1.2 and TLSv1.3.',
        });
      } else if (proto.supported.length > 0 && !proto.supported.includes('TLSv1.3')) {
        results.findings.push({
          id:          `SSL-NO-TLS13-${host}`,
          severity:    'low',
          confidence:  'confirmed',
          title:       `TLS 1.3 Not Supported: ${host}`,
          description: `The server at ${host} supports ${proto.supported.join(', ')} but not TLSv1.3. TLS 1.3 removes legacy cipher suites and improves performance and security.`,
          module:      'sslScan',
          affected:    host,
          remediation: 'Enable TLSv1.3 support on the server where possible.',
        });
      }
    } catch (err) {
      results.hosts.push({
        host,
        hasSSL:   false,
        status:   'error',
        daysLeft: null,
        error:    err.message,
      });
      results.summary.noSSL++;
    }
  });

  await Promise.allSettled(checks);

  // Sort: expired first, then expiring, then valid, then no_ssl
  const ORDER = { expired: 0, expiring: 1, valid: 2, no_ssl: 3, error: 4 };
  results.hosts.sort((a, b) => (ORDER[a.status] ?? 9) - (ORDER[b.status] ?? 9));

  onProgress(`SSL scan complete — ${results.summary.expired} expired, ${results.summary.expiring} expiring, ${results.summary.valid} valid`);
  return results;
}

// ── Protocol support prober ───────────────────────────────────────────────────
/**
 * Determine which TLS protocol versions a host accepts by attempting a handshake
 * pinned to each version (minVersion === maxVersion).
 *
 * Classifies each version into:
 *   - supported:  clean handshake completed (definitive).
 *   - accepted:   handshake reached a stage AFTER version negotiation, then
 *                 failed on cipher/key-exchange — the server DID speak this TLS
 *                 version (our modern OpenSSL just couldn't finish with a legacy
 *                 cipher). Treated as "likely supported".
 *   - unsupported: the server rejected the version (ssl_choose_client_version /
 *                 UNSUPPORTED_PROTOCOL) — definitive negative.
 *   - inconclusive: network error/timeout — we can't tell.
 *
 * This lets us flag deprecated TLS without false positives (we never infer
 * support from a plain network failure) while still catching legacy servers
 * whose old ciphers a modern client can't complete.
 */
async function probeProtocols(host, port = 443) {
  const VERSIONS = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
  const out = { supported: [], accepted: [], unsupported: [], inconclusive: [] };

  await Promise.all(VERSIONS.map(version => new Promise((resolve) => {
    let settled = false;
    const done = (bucket) => { if (!settled) { settled = true; out[bucket].push(version); resolve(); } };
    let sock;
    try {
      sock = tls.connect({
        host, port, servername: host,
        rejectUnauthorized: false,
        minVersion: version,
        maxVersion: version,
      }, () => { try { sock.destroy(); } catch (_) {} done('supported'); });
      sock.on('error', (e) => {
        try { sock.destroy(); } catch (_) {}
        const info = `${e && e.code || ''} ${e && e.message || ''}`.toLowerCase();
        if (/unsupported_protocol|unsupported protocol|wrong_version|wrong ssl version|choose_client_version|no protocols available|protocol_version/.test(info)) {
          done('unsupported');                       // server refused this version
        } else if (/econnrefused|etimedout|econnreset|timeout|socket hang up|getaddrinfo|enotfound|ehostunreach/.test(info)) {
          done('inconclusive');                      // couldn't complete the connection
        } else {
          done('accepted');                          // post-negotiation SSL error → version spoken
        }
      });
      sock.setTimeout(6000, () => { try { sock.destroy(); } catch (_) {} done('inconclusive'); });
    } catch (_) {
      done('inconclusive');
    }
  })));

  // Preserve canonical ordering within each bucket
  const order = (arr) => VERSIONS.filter(v => arr.includes(v));
  return { supported: order(out.supported), accepted: order(out.accepted), unsupported: order(out.unsupported), inconclusive: order(out.inconclusive) };
}

// ── TLS Certificate helper ────────────────────────────────────────────────────

function getCertInfo(host, port = 443, timeoutMs = 8000) {
  return new Promise((resolve) => {
    let resolved = false;
    const done = (val) => { if (!resolved) { resolved = true; resolve(val); } };

    const timer = setTimeout(() => done(null), timeoutMs);

    try {
      const sock = tls.connect(
        port,
        host,
        { servername: host, rejectUnauthorized: false },
        () => {
          clearTimeout(timer);
          try {
            const cert = sock.getPeerCertificate(true);
            const proto = sock.getProtocol();
            sock.destroy();

            if (!cert || !cert.valid_from) return done(null);

            const issuerO  = cert.issuer?.O  || '';
            const issuerCN = cert.issuer?.CN  || '';
            const subjectCN = cert.subject?.CN || host;
            const issuer   = issuerO || issuerCN || 'Unknown';
            const selfSigned = cert.fingerprint === cert.fingerprint256
              ? issuerCN === subjectCN
              : issuerO === (cert.subject?.O || '___NEVER___') && issuerCN === subjectCN;

            // SANs
            const san = [];
            if (cert.subjectaltname) {
              cert.subjectaltname.split(',').forEach(s => {
                const m = s.trim().match(/^DNS:(.+)$/i);
                if (m) san.push(m[1].trim());
              });
            }

            done({
              subject:   subjectCN,
              issuer,
              validFrom: cert.valid_from,
              validTo:   cert.valid_to,
              protocol:  proto,
              san,
              selfSigned: !!(issuerCN && issuerCN === subjectCN && !issuerO),
            });
          } catch (e) {
            sock.destroy();
            done(null);
          }
        }
      );
      sock.on('error', () => { clearTimeout(timer); done(null); });
      sock.setTimeout(timeoutMs, () => { sock.destroy(); done(null); });
    } catch (_) {
      clearTimeout(timer);
      done(null);
    }
  });
}

module.exports = { runSSLScan };
