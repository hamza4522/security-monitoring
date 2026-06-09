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
          title:       `Self-Signed SSL Certificate: ${host}`,
          description: `The certificate for ${host} is self-signed (issuer = subject). Browsers display "not trusted" warnings to visitors, which erodes user trust and can indicate a misconfiguration.`,
          module:      'sslScan',
          affected:    host,
          remediation: 'Replace the self-signed certificate with one issued by a trusted CA (e.g., Let\'s Encrypt, DigiCert).',
        });
      }

      // Weak protocol check
      if (info.protocol && (info.protocol === 'TLSv1' || info.protocol === 'TLSv1.1' || info.protocol === 'SSLv3')) {
        results.findings.push({
          id:          `SSL-WEAKPROTO-${host}`,
          severity:    'high',
          title:       `Weak TLS Protocol Negotiated: ${host} (${info.protocol})`,
          description: `The server negotiated ${info.protocol} which is deprecated and insecure. Attackers can exploit weaknesses in these protocol versions.`,
          module:      'sslScan',
          affected:    host,
          remediation: 'Disable TLSv1 and TLSv1.1. Configure server to only accept TLSv1.2 and TLSv1.3.',
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
