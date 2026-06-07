const { execCommand, isToolAvailable } = require('../utils/exec');

/**
 * Module 4: Service Fingerprinting & Version Detection
 * Tools: nmap -sV (primary), banner grabbing fallback
 */
async function runServiceFingerprint(domain, onProgress) {
  const results = { domain, services: [], softwareVersions: [], findings: [] };

  onProgress('Analyzing service banners and versions...');
  const SERVICE_PORTS = [22, 21, 25, 80, 443, 3306, 5432, 6379, 27017, 9200, 8080, 8443, 2375, 3389];

  const dns = require('dns').promises;
  let targetIP;
  try {
    const ips = await dns.resolve4(domain);
    targetIP = ips[0];
  } catch (_) {
    onProgress('Could not resolve domain for service fingerprinting');
    return results;
  }

  onProgress('Grabbing service banners...');
  const bannerResults = await grabBanners(targetIP, SERVICE_PORTS, onProgress);

  if (await isToolAvailable('nmap') && bannerResults.openPorts.length > 0) {
    onProgress(`Running nmap version detection on ${bannerResults.openPorts.length} open ports...`);
    try {
      const portList = bannerResults.openPorts.join(',');
      const output = await execCommand(
        `nmap -sV --version-intensity 3 -p ${portList} -oX - ${targetIP}`, 90000
      );
      parseNmapServices(output, results);
      onProgress(`Fingerprinted ${results.services.length} services`);
    } catch (e) { onProgress(`nmap error: ${e.message}`); }
  }

  bannerResults.services.forEach(svc => {
    if (!results.services.find(s => s.port === svc.port)) results.services.push(svc);
  });

  onProgress('Fingerprinting HTTP servers...');
  const httpServices = await fingerprintHTTP(domain, onProgress);
  results.services.push(...httpServices);

  onProgress('Checking software versions against known vulnerabilities...');
  results.softwareVersions = analyzeVersions(results.services);
  results.findings = generateServiceFindings(results);

  onProgress('Service fingerprinting complete');
  return results;
}

async function grabBanners(ip, ports, onProgress) {
  const net = require('net');
  const openPorts = [];
  const services = [];

  const checks = ports.map(port => {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let banner = '';
      let resolved = false;

      const done = () => {
        if (resolved) return;
        resolved = true;
        clearTimeout(safetyTimer);
        socket.destroy();
        if (banner) {
          services.push({
            port, ip,
            banner: banner.trim().substring(0, 200),
            service: detectServiceFromBanner(port, banner),
            version: extractVersion(banner),
          });
        }
        resolve();
      };

      // Hard safety timeout — ensures promise ALWAYS resolves
      const safetyTimer = setTimeout(done, 6000);

      socket.setTimeout(4000);
      socket.on('connect', () => {
        openPorts.push(port);
        if ([80, 8080, 8443, 443].includes(port)) {
          socket.write(`HEAD / HTTP/1.0\r\nHost: ${ip}\r\n\r\n`);
        }
        setTimeout(done, 3000); // If no data in 3s after connect, finish
      });
      socket.on('data', (data) => { banner += data.toString('utf8', 0, 512); done(); });
      socket.on('timeout', done);
      socket.on('error', done);
      socket.on('close', done);
      socket.connect(port, ip);
    });
  });

  await Promise.allSettled(checks);
  return { openPorts, services };
}

async function fingerprintHTTP(domain, onProgress) {
  const services = [];
  for (const scheme of ['https', 'http']) {
    try {
      const url = `${scheme}://${domain}`;
      const res = await fetch(url, {
        method: 'HEAD', redirect: 'follow',
        signal: AbortSignal.timeout(10000),
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)' },
      });
      const headers = Object.fromEntries(res.headers.entries());
      services.push({
        port: scheme === 'https' ? 443 : 80, protocol: scheme, service: 'HTTP',
        serverHeader: headers['server'] || '', poweredBy: headers['x-powered-by'] || '',
        via: headers['via'] || '',
        headers: {
          'x-frame-options': headers['x-frame-options'],
          'content-security-policy': headers['content-security-policy'],
          'strict-transport-security': headers['strict-transport-security'],
          'x-content-type-options': headers['x-content-type-options'],
          'x-xss-protection': headers['x-xss-protection'],
          'referrer-policy': headers['referrer-policy'],
          'permissions-policy': headers['permissions-policy'],
        },
        version: extractVersionFromServer(headers['server'] || ''),
        product: identifyProduct(headers['server'] || '', headers['x-powered-by'] || ''),
      });
      onProgress(`${scheme.toUpperCase()}: ${headers['server'] || 'server header hidden'}`);
    } catch (_) {}
  }
  return services;
}

function detectServiceFromBanner(port, banner) {
  const MAP = { 22:'SSH',21:'FTP',25:'SMTP',110:'POP3',143:'IMAP',3306:'MySQL',5432:'PostgreSQL',6379:'Redis',27017:'MongoDB',9200:'Elasticsearch',2375:'Docker',3389:'RDP' };
  if (MAP[port]) return MAP[port];
  if (banner.includes('SSH')) return 'SSH';
  if (banner.includes('FTP')) return 'FTP';
  if (banner.includes('SMTP') || banner.includes('220 ')) return 'SMTP';
  if (banner.includes('HTTP')) return 'HTTP';
  return 'unknown';
}

function extractVersion(banner) {
  const m = banner.match(/(\d+\.\d+(?:\.\d+)?(?:[_\-]\w+)?)/);
  return m ? m[1] : null;
}

function extractVersionFromServer(h) {
  if (!h) return null;
  const m = h.match(/[\w\/]+\/(\d+\.\d+(?:\.\d+)?)/);
  return m ? m[1] : null;
}

function identifyProduct(server, powered) {
  const c = `${server} ${powered}`.toLowerCase();
  if (c.includes('apache')) return 'Apache';
  if (c.includes('nginx')) return 'Nginx';
  if (c.includes('iis')) return 'IIS';
  if (c.includes('haproxy')) return 'HAProxy';
  if (c.includes('traefik')) return 'Traefik';
  if (c.includes('cloudflare')) return 'Cloudflare';
  if (c.includes('openresty')) return 'OpenResty/Nginx';
  if (c.includes('express')) return 'Express.js';
  if (c.includes('php')) return 'PHP';
  if (c.includes('asp.net')) return 'ASP.NET';
  return server || 'Unknown';
}

function parseNmapServices(xml, results) {
  const re = /<port protocol="(\w+)" portid="(\d+)">[\s\S]*?<state state="open"[\s\S]*?<service name="([^"]*)"[^>]*(?:product="([^"]*)")?[^>]*(?:version="([^"]*)")?/g;
  let m;
  while ((m = re.exec(xml)) !== null) {
    results.services.push({ port: parseInt(m[2]), protocol: m[1], service: m[3], product: m[4]||'', version: m[5]||'' });
  }
}

function analyzeVersions(services) {
  const VULNS = [
    { product: /openssh/i, version: /^[1-7]\.|8\.[0-3]/, severity: 'medium', issue: 'OpenSSH < 8.4 has known vulnerabilities' },
    { product: /apache/i, version: /^2\.[0-3]\.|2\.4\.[0-4][0-9]$/, severity: 'high', issue: 'Apache < 2.4.50 has path traversal (CVE-2021-41773)' },
    { product: /nginx/i, version: /^1\.[0-9]\.|1\.1[0-7]\./, severity: 'medium', issue: 'Nginx version may have known vulnerabilities' },
    { product: /openssl/i, version: /^1\.0\.|^1\.1\.0/, severity: 'high', issue: 'OpenSSL < 1.1.1 is EOL' },
    { product: /redis/i, version: /^[1-5]\./, severity: 'high', issue: 'Redis < 6.0 has security issues' },
    { product: /mysql/i, version: /^5\.[0-6]\./, severity: 'medium', issue: 'MySQL 5.6 is EOL' },
  ];
  return services.map(svc => {
    const fp = `${svc.product||''} ${svc.service||''}`.toLowerCase();
    const v = svc.version || '';
    const vuln = VULNS.find(p => p.product.test(fp) && v && p.version.test(v));
    return { ...svc, vulnerable: !!vuln, vulnerabilityNote: vuln?.issue||null, vulnSeverity: vuln?.severity||null };
  });
}

function generateServiceFindings(results) {
  const findings = [];
  results.services.filter(s => s.serverHeader && s.version).forEach(svc => {
    findings.push({
      id: `SVC-VERSION-${svc.port}`, severity: 'low',
      title: `Server Version Disclosure on Port ${svc.port}`,
      description: `Server header reveals: "${svc.serverHeader}". Exposing version info aids attackers.`,
      module: 'serviceFingerprint', affected: `Port ${svc.port}`,
      remediation: 'Configure server to suppress version info (ServerTokens Prod / server_tokens off).',
    });
  });

  const httpsvc = results.services.find(s => s.headers);
  if (httpsvc) {
    const checks = [
      { header: 'strict-transport-security', id: 'SVC-HSTS', severity: 'medium', title: 'Missing HSTS Header', rem: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains' },
      { header: 'content-security-policy', id: 'SVC-CSP', severity: 'medium', title: 'Missing Content Security Policy', rem: 'Implement a Content-Security-Policy header.' },
      { header: 'x-frame-options', id: 'SVC-XFO', severity: 'low', title: 'Missing X-Frame-Options', rem: 'Add: X-Frame-Options: SAMEORIGIN' },
      { header: 'x-content-type-options', id: 'SVC-XCTO', severity: 'low', title: 'Missing X-Content-Type-Options', rem: 'Add: X-Content-Type-Options: nosniff' },
    ];
    checks.forEach(sh => {
      if (!httpsvc.headers[sh.header]) {
        findings.push({ id: sh.id, severity: sh.severity, title: sh.title,
          description: `Missing ${sh.header} security header.`, module: 'serviceFingerprint', remediation: sh.rem });
      }
    });
    if (!results.services.find(s => s.protocol === 'https' || s.port === 443)) {
      findings.push({ id: 'SVC-TLS', severity: 'high', title: 'No HTTPS Detected',
        description: 'No HTTPS detected, data in transit is exposed.', module: 'serviceFingerprint',
        remediation: 'Enable TLS and redirect HTTP to HTTPS.' });
    }
  }

  results.softwareVersions.filter(s => s.vulnerable).forEach(svc => {
    findings.push({
      id: `SVC-VULN-${svc.port}`, severity: svc.vulnSeverity || 'medium',
      title: `Potentially Vulnerable: ${svc.product} ${svc.version}`,
      description: svc.vulnerabilityNote, module: 'serviceFingerprint',
      affected: `Port ${svc.port}: ${svc.product} ${svc.version}`,
      remediation: `Update ${svc.product} to the latest stable version.`,
    });
  });

  return findings;
}

module.exports = { runServiceFingerprint };
