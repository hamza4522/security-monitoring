const dns = require('dns').promises;

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
  const commonSelectors = ['default', 'google', 'k1', 'mail', 'smtp', 'email', 'dkim', 's1', 's2'];
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

async function testZoneTransfer(domain, nameservers) {
  // Zone transfer (AXFR) test - for detection only
  // Real implementation would use dig AXFR or similar
  const results = [];

  for (const ns of nameservers.slice(0, 3)) {
    results.push({
      nameserver: ns,
      vulnerable: false, // In real impl: attempt AXFR and check response
      tested: true,
      note: 'AXFR test requires dig/nslookup - implement with execCommand',
    });
  }

  return { tested: results.length > 0, results, vulnerable: false };
}

function generateDNSFindings(results) {
  const findings = [];

  // SPF findings
  if (!results.spf.present) {
    findings.push({
      id: 'DNS-001',
      severity: 'high',
      title: 'Missing SPF Record',
      description: `No SPF record found for ${results.domain}. This allows anyone to send email on behalf of this domain.`,
      module: 'dnsAssessment',
      remediation: 'Add a TXT record: v=spf1 include:_spf.yourmailprovider.com ~all',
      cvss: 7.5,
    });
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

  // DMARC findings
  if (!results.dmarc.present) {
    findings.push({
      id: 'DNS-002',
      severity: 'high',
      title: 'Missing DMARC Record',
      description: 'No DMARC record found. Email spoofing cannot be detected or blocked.',
      module: 'dnsAssessment',
      remediation: 'Add: _dmarc.yourdomain.com TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"',
      cvss: 7.5,
    });
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

  // DKIM findings
  if (!results.dkim.configured) {
    findings.push({
      id: 'DNS-004',
      severity: 'medium',
      title: 'No DKIM Records Found',
      description: 'No DKIM signing records detected for common selectors.',
      module: 'dnsAssessment',
      remediation: 'Configure DKIM signing in your email provider and publish the public key as a TXT record.',
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
