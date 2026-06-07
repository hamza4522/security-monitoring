const { execCommand, isToolAvailable } = require('../utils/exec');

/**
 * Module 1: Asset Discovery & Attack Surface Mapping
 * Tools: subfinder, httpx, dnsx, nmap (for live host detection)
 */
async function runAssetDiscovery(domain, onProgress) {
  const results = {
    domain,
    subdomains: [],
    liveHosts: [],
    ipAddresses: [],
    cloudProviders: [],
    cdnProviders: [],
    wafDetected: [],
    findings: [],
    toolsUsed: [],
  };

  // --- Subdomain Enumeration (subfinder) ---
  onProgress('Starting subdomain enumeration with subfinder...');
  if (await isToolAvailable('subfinder')) {
    results.toolsUsed.push('subfinder');
    try {
      const output = await execCommand(`subfinder -d ${domain} -silent -timeout 30`, 60000);
      const subs = output.split('\n').map(s => s.trim()).filter(Boolean);
      results.subdomains = [...new Set([domain, ...subs])];
      onProgress(`Found ${results.subdomains.length} subdomains`);
    } catch (e) {
      onProgress(`subfinder error: ${e.message}`);
      // Fallback: try basic DNS enumeration
      results.subdomains = await basicSubdomainEnum(domain, onProgress);
    }
  } else {
    onProgress('subfinder not found, using DNS fallback...');
    results.subdomains = await basicSubdomainEnum(domain, onProgress);
  }

  // --- DNS Resolution (dnsx) ---
  onProgress('Resolving IP addresses with dnsx...');
  if (await isToolAvailable('dnsx') && results.subdomains.length > 0) {
    results.toolsUsed.push('dnsx');
    try {
      const input = results.subdomains.join('\n');
      const output = await execCommand(`echo "${input}" | dnsx -silent -a -resp`, 60000);
      const lines = output.split('\n').filter(Boolean);
      const ipMap = {};
      lines.forEach(line => {
        const match = line.match(/^(.+?)\s+\[(.+?)\]/);
        if (match) ipMap[match[1]] = match[2].split(',').map(ip => ip.trim());
      });
      results.ipAddresses = Object.entries(ipMap).map(([host, ips]) => ({ host, ips }));
      onProgress(`Resolved ${results.ipAddresses.length} hosts to IP addresses`);
    } catch (e) {
      onProgress(`dnsx error: ${e.message}`);
      results.ipAddresses = await dnsResolveBasic(results.subdomains, onProgress);
    }
  } else {
    results.ipAddresses = await dnsResolveBasic(results.subdomains, onProgress);
  }

  // --- Live Host Validation (httpx) ---
  onProgress('Validating live hosts with httpx...');
  if (await isToolAvailable('httpx') && results.subdomains.length > 0) {
    results.toolsUsed.push('httpx');
    try {
      const input = results.subdomains.join('\n');
      const output = await execCommand(
        `echo "${input}" | httpx -silent -status-code -title -tech-detect -cdn -waf -timeout 10`,
        120000
      );
      const lines = output.split('\n').filter(Boolean);
      results.liveHosts = lines.map(parsehttpxLine).filter(Boolean);
      onProgress(`Found ${results.liveHosts.length} live HTTP/HTTPS hosts`);

      // Extract CDN/WAF/Cloud info
      results.liveHosts.forEach(host => {
        if (host.cdn) results.cdnProviders.push({ host: host.url, provider: host.cdn });
        if (host.waf) results.wafDetected.push({ host: host.url, waf: host.waf });
        if (host.cloud) results.cloudProviders.push({ host: host.url, provider: host.cloud });
      });
    } catch (e) {
      onProgress(`httpx error: ${e.message}`);
      results.liveHosts = await httpProbeBasic(results.subdomains, onProgress);
    }
  } else {
    onProgress('httpx not found, using basic HTTP probing...');
    results.liveHosts = await httpProbeBasic(results.subdomains, onProgress);
  }

  // --- Subdomain Takeover Detection ---
  onProgress('Checking for subdomain takeover vulnerabilities...');
  const takeoverFindings = checkSubdomainTakeover(results.subdomains, results.ipAddresses);
  results.findings.push(...takeoverFindings);

  // --- Generate Findings ---
  if (results.subdomains.length > 50) {
    results.findings.push({
      id: 'ASSET-001',
      severity: 'info',
      title: 'Large Attack Surface',
      description: `${results.subdomains.length} subdomains discovered, indicating a large attack surface.`,
      module: 'assetDiscovery',
      remediation: 'Audit and decommission unused subdomains. Implement subdomain inventory tracking.',
    });
  }

  if (results.wafDetected.length === 0 && results.liveHosts.length > 0) {
    results.findings.push({
      id: 'ASSET-002',
      severity: 'medium',
      title: 'No WAF Detected',
      description: 'No Web Application Firewall was detected on any live hosts.',
      module: 'assetDiscovery',
      remediation: 'Consider deploying a WAF (Cloudflare, AWS WAF, Akamai) to protect web applications.',
    });
  }

  onProgress('Asset discovery complete');
  return results;
}

// ---- Fallback: Subdomain enum via crt.sh & common wordlist ----
async function basicSubdomainEnum(domain, onProgress) {
  const dns = require('dns').promises;
  const found = new Set([domain]);

  onProgress('Querying crt.sh Certificate Transparency logs...');
  try {
    const res = await fetch(`https://crt.sh/?q=%25.${domain}&output=json`, { signal: AbortSignal.timeout(15000) });
    if (res.ok) {
      const data = await res.json();
      data.forEach(entry => {
        if (entry.name_value) {
          entry.name_value.split('\n').forEach(name => {
            name = name.trim().toLowerCase();
            if (name && !name.includes('*')) found.add(name);
          });
        }
      });
      onProgress(`crt.sh found ${found.size} unique subdomains`);
    }
  } catch (err) {
    onProgress(`crt.sh error: ${err.message}`);
  }

  // Also do basic DNS brute force
  onProgress('Running basic wordlist enumeration...');
  const commonSubs = [
    'www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2', 'vpn', 'api',
    'dev', 'staging', 'test', 'admin', 'portal', 'blog', 'shop', 'app',
    'cdn', 'static', 'assets', 'media', 'img', 'images', 'download',
    'support', 'help', 'docs', 'wiki', 'forum', 'community', 'mobile',
    'beta', 'alpha', 'prod', 'production', 'internal', 'intranet', 'git',
    'gitlab', 'jenkins', 'ci', 'k8s', 'docker', 'registry', 'monitor',
    'grafana', 'kibana', 'elastic', 'db', 'database', 'redis', 'queue',
  ];

  const checks = commonSubs.map(async (sub) => {
    const fqdn = `${sub}.${domain}`;
    if (found.has(fqdn)) return;
    try {
      await dns.resolve(fqdn);
      found.add(fqdn);
    } catch (_) {}
  });

  await Promise.allSettled(checks);
  const arr = Array.from(found);
  onProgress(`Subdomain discovery finished with ${arr.length} subdomains`);
  return arr;
}

// ---- Fallback: Basic DNS resolution ----
async function dnsResolveBasic(subdomains, onProgress) {
  const dns = require('dns').promises;
  const results = [];
  const batch = subdomains.slice(0, 100); // Limit for speed

  const checks = batch.map(async (host) => {
    try {
      const addrs = await dns.resolve4(host);
      results.push({ host, ips: addrs });
    } catch (_) {}
  });

  await Promise.allSettled(checks);
  onProgress(`Resolved ${results.length} hosts`);
  return results;
}

// ---- Fallback: Basic HTTP probing using native fetch ----
async function httpProbeBasic(subdomains, onProgress) {
  const live = [];
  const batch = subdomains.slice(0, 50);

  const checks = batch.map(async (host) => {
    for (const scheme of ['https', 'http']) {
      try {
        const url = `${scheme}://${host}`;
        const res = await fetch(url, {
          method: 'HEAD',
          redirect: 'follow',
          signal: AbortSignal.timeout(8000), // 8s hard timeout per request
        });
        live.push({ url, status: res.status, host });
        break;
      } catch (_) {}
    }
  });

  await Promise.allSettled(checks);
  onProgress(`HTTP probe found ${live.length} live hosts`);
  return live;
}

// ---- Parse httpx output line ----
function parsehttpxLine(line) {
  try {
    const urlMatch = line.match(/^(https?:\/\/[^\s]+)/);
    const statusMatch = line.match(/\[(\d{3})\]/);
    const titleMatch = line.match(/\[([^\]]+)\].*?\[([^\]]+)\].*?\[([^\]]+)\]/);
    if (!urlMatch) return null;
    return {
      url: urlMatch[1],
      status: statusMatch ? parseInt(statusMatch[1]) : null,
      raw: line,
    };
  } catch (_) {
    return null;
  }
}

// ---- Check for potential subdomain takeovers ----
function checkSubdomainTakeover(subdomains, ipAddresses) {
  const findings = [];
  const resolvedHosts = new Set(ipAddresses.map(r => r.host));

  // Subdomains that don't resolve are potential dangling DNS entries
  const dangling = subdomains.filter(s => !resolvedHosts.has(s));
  dangling.forEach(sub => {
    findings.push({
      id: 'ASSET-TAKEOVER-001',
      severity: 'high',
      title: 'Potential Subdomain Takeover',
      description: `Subdomain ${sub} has DNS records but no IP resolution. May be vulnerable to takeover.`,
      module: 'assetDiscovery',
      affected: sub,
      remediation: 'Remove DNS records for decommissioned services, or point to active infrastructure.',
    });
  });

  return findings.slice(0, 10); // Cap at 10 findings
}

module.exports = { runAssetDiscovery };
