'use strict';
/**
 * whoisLookup.js — WHOIS & IP Intelligence Module
 *
 * Uses:
 *   - https://rdap.org/domain/{domain}  (IANA RDAP bootstrap — free, no key)
 *   - http://ip-api.com/json/{ip}       (45 req/min free tier — no key needed)
 *   - Node.js dns.promises (built-in)
 */

const https = require('https');
const http  = require('http');
const dns   = require('dns').promises;

// ── HTTP helper ───────────────────────────────────────────────────────────────

function fetchJson(url, timeoutMs = 9000) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, {
      headers: { 'User-Agent': 'ReconScan/1.0', 'Accept': 'application/json' },
    }, (res) => {
      let raw = '';
      res.on('data', c => { raw += c; });
      res.on('end', () => {
        try { resolve(JSON.parse(raw)); } catch (_) { resolve(null); }
      });
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error('timeout')); });
  });
}

// ── Main module export ────────────────────────────────────────────────────────

async function runWhoisLookup(domain, onProgress) {
  const findings = [];
  const result = {
    domain,
    registrar:        null,
    registrantOrg:    null,
    registrationDate: null,
    expirationDate:   null,
    updatedDate:      null,
    daysUntilExpiry:  null,
    nameservers:      [],
    domainStatus:     [],
    ipGeo:            [],
  };

  // ── RDAP Domain Registration ──────────────────────────────────────────────
  onProgress('Fetching RDAP registration data…');
  try {
    // Try RDAP bootstrap through rdap.org which handles TLD routing automatically
    const rdap = await fetchJson(`https://rdap.org/domain/${domain}`);
    if (rdap && !rdap.errorCode) {
      // Registrar
      const registrarEntity = (rdap.entities || []).find(e => (e.roles || []).includes('registrar'));
      if (registrarEntity) {
        const fn = (registrarEntity.vcardArray?.[1] || []).find(v => v[0] === 'fn');
        result.registrar = fn?.[3] || registrarEntity.handle || null;
      }

      // Registrant org
      const registrantEntity = (rdap.entities || []).find(e => (e.roles || []).includes('registrant'));
      if (registrantEntity) {
        const org = (registrantEntity.vcardArray?.[1] || []).find(v => v[0] === 'org');
        result.registrantOrg = org?.[3] || null;
      }

      // Events → dates
      const events = rdap.events || [];
      result.registrationDate = events.find(e => e.eventAction === 'registration')?.eventDate  || null;
      result.expirationDate   = events.find(e => e.eventAction === 'expiration')?.eventDate    || null;
      result.updatedDate      = events.find(e => e.eventAction === 'last changed')?.eventDate  || null;

      // Name servers
      result.nameservers = (rdap.nameservers || [])
        .map(ns => (ns.ldhName || '').toLowerCase())
        .filter(Boolean);

      // Domain status codes
      result.domainStatus = rdap.status || [];

      // ── Expiry findings ──────────────────────────────────────────────────
      if (result.expirationDate) {
        const expiry = new Date(result.expirationDate);
        const daysLeft = Math.floor((expiry - Date.now()) / 86_400_000);
        result.daysUntilExpiry = daysLeft;

        if (daysLeft < 0) {
          findings.push({
            id: 'whois-domain-expired',
            severity: 'critical',
            title: 'Domain Registration Expired',
            description: `The domain ${domain} registration expired ${Math.abs(daysLeft)} day(s) ago (${result.expirationDate}). The domain is at immediate risk of hijacking.`,
            remediation: 'Renew the domain registration immediately through your registrar before another party claims it.',
            module: 'whoisLookup', affected: domain,
          });
        } else if (daysLeft <= 30) {
          findings.push({
            id: 'whois-expiring-soon',
            severity: 'high',
            title: `Domain Expiring in ${daysLeft} Days`,
            description: `${domain} expires on ${new Date(result.expirationDate).toLocaleDateString()}. Missing renewal causes outages and domain hijacking risk.`,
            remediation: 'Renew immediately through your registrar and enable auto-renew.',
            module: 'whoisLookup', affected: domain,
          });
        } else if (daysLeft <= 90) {
          findings.push({
            id: 'whois-expiring-90d',
            severity: 'medium',
            title: `Domain Expiring in ${daysLeft} Days`,
            description: `${domain} expires on ${new Date(result.expirationDate).toLocaleDateString()}. Plan renewal now to avoid last-minute rush.`,
            remediation: 'Schedule domain renewal well before expiry. Enable auto-renew if available.',
            module: 'whoisLookup', affected: domain,
          });
        }
      }

      // ── Transfer lock check ──────────────────────────────────────────────
      const hasTransferLock = result.domainStatus.some(s =>
        s.toLowerCase().includes('clienttransferprohibited')
      );
      if (!hasTransferLock && result.domainStatus.length > 0) {
        findings.push({
          id: 'whois-no-transfer-lock',
          severity: 'medium',
          title: 'Domain Transfer Lock Not Enabled',
          description: `${domain} is missing the clientTransferProhibited status flag, which could allow an unauthorized registrar transfer.`,
          remediation: 'Enable Transfer Lock (clientTransferProhibited) in your registrar control panel.',
          module: 'whoisLookup', affected: domain,
        });
      }
    }
  } catch (err) {
    onProgress(`RDAP lookup failed: ${err.message}`);
  }

  // ── IP Geolocation ────────────────────────────────────────────────────────
  onProgress('Resolving IP addresses and querying geolocation…');
  try {
    const v4Addresses = await dns.resolve4(domain).catch(() => []);
    const ipResults   = [];

    for (const ip of v4Addresses.slice(0, 3)) {
      try {
        const geo = await fetchJson(
          `http://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,isp,org,as,hosting,proxy,mobile`
        );
        if (geo && geo.status === 'success') {
          ipResults.push({
            ip,
            country:     geo.country,
            countryCode: geo.countryCode,
            region:      geo.regionName,
            city:        geo.city,
            isp:         geo.isp,
            org:         geo.org,
            asn:         geo.as,
            isHosting:   geo.hosting,
            isProxy:     geo.proxy,
            isMobile:    geo.mobile,
          });

          // Proxy / anonymizing service
          if (geo.proxy) {
            findings.push({
              id: `whois-proxy-${ip}`,
              severity: 'medium',
              title: `IP Identified as Proxy / VPN: ${ip}`,
              description: `${ip} is flagged as a proxy or VPN endpoint. This could indicate privacy-conscious hosting or an attempt to obscure infrastructure origin.`,
              remediation: 'Verify this is intentional infrastructure design. If unexpected, investigate your hosting configuration.',
              module: 'whoisLookup', affected: ip,
            });
          }

          // Geopolitical risk countries (common compliance concern list)
          const watchlistCCs = ['KP', 'IR', 'SY', 'CU'];
          if (watchlistCCs.includes(geo.countryCode)) {
            findings.push({
              id: `whois-geo-watchlist-${ip}`,
              severity: 'high',
              title: `Server Hosted in Sanctioned Region: ${geo.country}`,
              description: `${ip} is geolocated to ${geo.city}, ${geo.country}. Hosting in this region may violate international sanctions and data sovereignty regulations.`,
              remediation: 'Review data residency and sanctions compliance requirements. Migrate hosting if applicable.',
              module: 'whoisLookup', affected: ip,
            });
          }
        }
      } catch (_) { /* individual IP failure is non-fatal */ }
    }
    result.ipGeo = ipResults;
  } catch (err) {
    onProgress(`IP geolocation error: ${err.message}`);
  }

  return { ...result, findings };
}

module.exports = { runWhoisLookup };
