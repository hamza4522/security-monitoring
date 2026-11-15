const dns = require('dns').promises;
const net = require('net');

/**
 * Module 2: DNS & Email Security Assessment
 * Uses Node.js built-in dns module + manual record inspection
 */
async function runDNSAssessment(domain, onProgress) {
  const results = {
    domain,
    records: {},
    spf: null,
    dmarc: null,
    dkim: null,
    dnssec: null,
    zoneTransfer: null,
    nameservers: [],
    issues: [],
    findings: [],
  };

  // --- A Records ---
  onProgress('Querying A records...');
  try {
    results.records.a = await dns.resolve4(domain);
  } catch (e) {
    results.records.a = [];
  }

  // --- AAAA Records ---
  onProgress('Querying AAAA records...');
  try {
    results.records.aaaa = await dns.resolve6(domain);
  } catch (e) {
    results.records.aaaa = [];
  }

  // --- MX Records ---
  onProgress('Querying MX records...');
  try {
    const mx = await dns.resolveMx(domain);
    results.records.mx = mx.sort((a, b) => a.priority - b.priority);
  } catch (e) {
    results.records.mx = [];
  }

  // --- TXT Records ---
  onProgress('Querying TXT records...');
  try {
    const txt = await dns.resolveTxt(domain);
    results.records.txt = txt.map(r => r.join(''));
  } catch (e) {
    results.records.txt = [];
  }

  // --- NS Records ---
  onProgress('Querying NS records...');
  try {
    results.nameservers = await dns.resolveNs(domain);
  } catch (e) {
    results.nameservers = [];
  }

  // --- SPF Analysis ---
  onProgress('Analyzing SPF record...');
  results.spf = analyzeSPF(results.records.txt, domain);

  // --- DMARC Analysis ---
  onProgress('Analyzing DMARC record...');
  results.dmarc = await analyzeDMARC(domain);

  // --- DKIM Check ---
  onProgress('Checking DKIM records...');
  results.dkim = await checkDKIM(domain);

  // --- DNSSEC Check ---
  onProgress('Checking DNSSEC...');
  results.dnssec = await checkDNSSEC(domain);

  // --- Zone Transfer Test ---
  onProgress('Testing zone transfer...');
  results.zoneTransfer = await testZoneTransfer(domain, results.nameservers);

  // --- Generate Findings ---
  results.findings = generateDNSFindings(results);

  onProgress('DNS assessment complete');
  return results;
}

function analyzeSPF(txtRecords, domain) {
  const spfRecord = txtRecords.find(r => r.startsWith('v=spf1'));
  if (!spfRecord) {
    return {
      present: false,
      record: null,
      policy: null,
      mechanisms: [],
      issues: ['No SPF record found'],
    };
  }

  const parts = spfRecord.split(' ').filter(Boolean);
  const mechanisms = parts.slice(1);
  const hasAll = mechanisms.find(m => m === '+all' || m === '~all' || m === '-all' || m === '?all');
  const allPolicy = hasAll || 'missing';

  const issues = [];
  if (allPolicy === '+all') issues.push('SPF allows all senders (+all) — effectively no restriction');
  if (allPolicy === '?all') issues.push('SPF neutral policy (?all) provides no protection');
  if (allPolicy === 'missing') issues.push('SPF record has no "all" mechanism');

  const includes = mechanisms.filter(m => m.startsWith('include:'));
  if (includes.length > 10) issues.push(`Too many SPF includes (${includes.length}) — may exceed DNS lookup limit`);

  return {
    present: true,
    record: spfRecord,
    policy: allPolicy,
    mechanisms: mechanisms,
    lookupCount: includes.length,
    issues,
  };
}

async function analyzeDMARC(domain) {
  try {
    const dmarcDomain = `_dmarc.${domain}`;
    const txt = await dns.resolveTxt(dmarcDomain);
    const dmarcRecord = txt.map(r => r.join('')).find(r => r.startsWith('v=DMARC1'));

    if (!dmarcRecord) {
      return { present: false, record: null, policy: null, issues: ['No DMARC record found'] };
    }

    const params = {};
    dmarcRecord.split(';').forEach(part => {
      const [k, v] = part.trim().split('=');
      if (k && v) params[k.trim()] = v.trim();
    });

    const issues = [];
    if (params.p === 'none') issues.push('DMARC policy is "none" — no enforcement, only monitoring');
    if (!params.rua) issues.push('No aggregate report URI (rua) configured');
    if (!params.ruf) issues.push('No forensic report URI (ruf) configured');
    const pct = parseInt(params.pct || '100');
    if (pct < 100) issues.push(`DMARC policy only applies to ${pct}% of messages`);

    return {
      present: true,
      record: dmarcRecord,
      policy: params.p,
      subdomainPolicy: params.sp,
      reportEmail: params.rua,
      percentage: pct,
      params,
      issues,
    };
  } catch (e) {
    return { present: false, record: null, policy: null, issues: ['No DMARC record found'] };
  }
}

async function checkDKIM(domain) {
  // DKIM selectors are arbitrary per-sender, so this is a best-effort probe of
  // widely-used selectors. Notably includes Microsoft 365 (selector1/selector2),
  // Google, Fastmail (fm1-3), Mailchimp (k1/k2/k3), Postmark, SendGrid, Amazon SES.
  const commonSelectors = [
    'default', 'google', 'k1', 'k2', 'k3', 'mail', 'smtp', 'email', 'dkim', 's1', 's2',
    'selector1', 'selector2',        // Microsoft 365 / Outlook
    'fm1', 'fm2', 'fm3',             // Fastmail
    'mandrill', 'mte1', 'mte2',      // Mailchimp Transactional / others
    'pm', 'pm1',                      // Postmark
    'scph', 's1024', 'sig1',         // SendGrid / various
    'amazonses', 'ses',              // Amazon SES
    'zoho', 'zmail',                 // Zoho
    'protonmail', 'protonmail2', 'protonmail3',
  ];
  const found = [];

  const checks = commonSelectors.map(async (selector) => {
    try {
      const dkimDomain = `${selector}._domainkey.${domain}`;
      const txt = await dns.resolveTxt(dkimDomain);
      const record = txt.map(r => r.join('')).find(r => r.includes('v=DKIM1') || r.includes('k=rsa'));
      if (record) {
        found.push({ selector, record: record.substring(0, 100) + '...' });
      }
    } catch (_) {}
  });

  await Promise.allSettled(checks);
  return { configured: found.length > 0, selectors: found };
}

async function checkDNSSEC(domain) {
  try {
    const ds = await dns.resolve(domain, 'DS');
    return { enabled: true, records: ds };
  } catch (_) {
    try {
      const dnskey = await dns.resolve(domain, 'DNSKEY');
      return { enabled: true, records: dnskey };
    } catch (_) {
      return { enabled: false, records: [] };
    }
  }
}

// ── AXFR (zone transfer) — self-contained raw DNS over TCP ────────────────────
/**
 * Encode a DNS QNAME (sequence of length-prefixed labels, null-terminated).
 */
function encodeQName(domain) {
  const labels = domain.replace(/\.$/, '').split('.');
  const bufs = labels.map(l => {
    const b = Buffer.from(l, 'ascii');
    return Buffer.concat([Buffer.from([b.length]), b]);
  });
  return Buffer.concat([...bufs, Buffer.from([0])]);
}

/**
 * Attempt an AXFR against one nameserver. Returns { vulnerable, rcode, answerCount }.
 * AXFR is a TCP-only query (type 252). A server that permits transfer replies with
 * RCODE=0 and streams the zone (many answer records, starting/ending with SOA).
 * A locked-down server replies REFUSED (RCODE=5) or drops the connection.
 */
function attemptAXFR(nsHost, domain, timeoutMs = 8000) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (val) => { if (!settled) { settled = true; try { sock.destroy(); } catch (_) {} resolve(val); } };

    // Build the AXFR query message.
    const id = Math.floor(Math.random() * 65536);
    const header = Buffer.alloc(12);
    header.writeUInt16BE(id, 0);
    header.writeUInt16BE(0x0000, 2);  // standard query, RD=0
    header.writeUInt16BE(1, 4);       // QDCOUNT = 1
    const qname = encodeQName(domain);
    const qtail = Buffer.alloc(4);
    qtail.writeUInt16BE(252, 0);      // QTYPE = AXFR
    qtail.writeUInt16BE(1, 2);        // QCLASS = IN
    const msg = Buffer.concat([header, qname, qtail]);
    const framed = Buffer.concat([Buffer.from([msg.length >> 8, msg.length & 0xff]), msg]);

    let buf = Buffer.alloc(0);
    let totalAnswers = 0;
    let firstRcode = null;

    const sock = net.connect({ host: nsHost, port: 53 });
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => sock.write(framed));
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      // Parse as many length-prefixed DNS messages as are complete in the buffer.
      while (buf.length >= 2) {
        const len = buf.readUInt16BE(0);
        if (buf.length < 2 + len) break;
        const message = buf.slice(2, 2 + len);
        buf = buf.slice(2 + len);
        if (message.length >= 12) {
          const flags = message.readUInt16BE(2);
          const rcode = flags & 0x0f;
          if (firstRcode === null) firstRcode = rcode;
          totalAnswers += message.readUInt16BE(6); // ANCOUNT
        }
        // A successful AXFR returns the full zone (≥2 records: SOA … SOA).
        if (totalAnswers >= 2) {
          return finish({ vulnerable: true, rcode: firstRcode ?? 0, answerCount: totalAnswers });
        }
      }
    });
    sock.on('timeout', () => finish({ vulnerable: totalAnswers >= 2, rcode: firstRcode, answerCount: totalAnswers, note: 'timeout' }));
    sock.on('error', () => finish({ vulnerable: false, rcode: firstRcode, answerCount: totalAnswers, note: 'connection error' }));
    sock.on('close', () => finish({ vulnerable: totalAnswers >= 2, rcode: firstRcode, answerCount: totalAnswers }));
  });
}

async function testZoneTransfer(domain, nameservers) {
  const results = [];
  let vulnerable = false;

  for (const ns of nameservers.slice(0, 3)) {
    // Resolve the nameserver hostname to an IP (AXFR connects directly to it).
    let nsIP = ns;
    try {
      const addrs = await dns.resolve4(ns.replace(/\.$/, ''));
      nsIP = addrs[0] || ns;
    } catch (_) { /* fall back to the hostname */ }

    try {
      const r = await attemptAXFR(nsIP, domain);
      results.push({
        nameserver: ns,
        tested: true,
        vulnerable: r.vulnerable,
        answerRecords: r.answerCount || 0,
        rcode: r.rcode,
      });
      if (r.vulnerable) vulnerable = true;
    } catch (e) {
      results.push({ nameserver: ns, tested: true, vulnerable: false, error: e.message });
    }
  }

  return { tested: results.some(r => r.tested), results, vulnerable };
}

function generateDNSFindings(results) {
  const findings = [];
  const hasMailServers = results.records.mx && results.records.mx.length > 0;

  // SPF findings — only report as high severity if domain actually accepts/sends email
  if (!results.spf.present) {
    if (hasMailServers) {
      findings.push({
        id: 'DNS-001',
        severity: 'high',
        title: 'Missing SPF Record',
        description: `No SPF record found for ${results.domain}. Since MX records exist, this allows anyone to send spoofed email on behalf of this domain.`,
        module: 'dnsAssessment',
        remediation: 'Add a TXT record: v=spf1 include:_spf.yourmailprovider.com ~all',
        cvss: 7.5,
      });
    } else {
      findings.push({
        id: 'DNS-001-INFO',
        severity: 'info',
        title: 'No SPF Record (No MX Records Found)',
        description: `No SPF record found for ${results.domain}. However, no MX records were detected either, so email spoofing risk is lower. Best practice is to publish "v=spf1 -all" to block all sending.`,
        module: 'dnsAssessment',
        remediation: 'If this domain will never send email, publish: v=spf1 -all',
        cvss: 0,
      });
    }
  } else if (results.spf.issues.length > 0) {
    results.spf.issues.forEach((issue, i) => {
      findings.push({
        id: `DNS-SPF-${i + 1}`,
        severity: results.spf.policy === '+all' ? 'critical' : 'medium',
        title: `SPF Misconfiguration: ${issue}`,
        description: issue,
        module: 'dnsAssessment',
        remediation: 'Review SPF record and tighten policy to -all where possible.',
      });
    });
  }

  // DMARC findings — only report as high if MX records exist
  if (!results.dmarc.present) {
    if (hasMailServers) {
      findings.push({
        id: 'DNS-002',
        severity: 'high',
        title: 'Missing DMARC Record',
        description: 'No DMARC record found on an active email domain. Email spoofing cannot be detected or blocked by receivers.',
        module: 'dnsAssessment',
        remediation: 'Add: _dmarc.yourdomain.com TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"',
        cvss: 7.5,
      });
    } else {
      findings.push({
        id: 'DNS-002-INFO',
        severity: 'info',
        title: 'No DMARC Record (No MX Records Found)',
        description: 'No DMARC record found. Since no MX records exist, consider publishing "v=DMARC1; p=reject" to protect your domain brand from phishing.',
        module: 'dnsAssessment',
        remediation: 'Publish: _dmarc.yourdomain.com TXT "v=DMARC1; p=reject"',
        cvss: 0,
      });
    }
  } else if (results.dmarc.policy === 'none') {
    findings.push({
      id: 'DNS-003',
      severity: 'medium',
      title: 'DMARC Policy Set to None',
      description: 'DMARC is configured but with p=none, meaning no action is taken on failing emails.',
      module: 'dnsAssessment',
      remediation: 'Graduate DMARC policy from p=none to p=quarantine, then p=reject after reviewing reports.',
    });
  }

  // DKIM findings — only report if domain handles email
  if (!results.dkim.configured && hasMailServers) {
    findings.push({
      id: 'DNS-004',
      severity: 'low',
      confidence: 'possible',
      title: 'No DKIM Records Found (Common Selectors)',
      description: 'No DKIM signing records were found for a list of common selectors on this active email domain. NOTE: DKIM selectors are arbitrary and provider-specific — a custom selector would not be detected by this probe, so this is not conclusive. Verify manually before acting.',
      module: 'dnsAssessment',
      remediation: 'Confirm whether DKIM is configured with your email provider. If not, enable DKIM signing and publish the public key as a TXT record at <selector>._domainkey.',
    });
  }

  // DNSSEC findings
  if (!results.dnssec.enabled) {
    findings.push({
      id: 'DNS-005',
      severity: 'low',
      title: 'DNSSEC Not Enabled',
      description: 'DNSSEC is not configured, leaving DNS responses vulnerable to cache poisoning attacks.',
      module: 'dnsAssessment',
      remediation: 'Enable DNSSEC through your domain registrar and DNS provider.',
    });
  }

  // Zone transfer
  if (results.zoneTransfer.vulnerable) {
    findings.push({
      id: 'DNS-006',
      severity: 'critical',
      title: 'DNS Zone Transfer Exposed',
      description: 'Zone transfer (AXFR) is allowed, exposing the complete DNS zone to any requester.',
      module: 'dnsAssessment',
      remediation: 'Restrict zone transfers to authorized secondary DNS servers only.',
      cvss: 9.1,
    });
  }

  return findings;
}

module.exports = { runDNSAssessment };
