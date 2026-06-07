const { execCommand, isToolAvailable } = require('../utils/exec');
const dns = require('dns').promises;

/**
 * Module 3: Network Discovery & Port Scanning
 * Tools: nmap (primary), masscan (fast scan), basic TCP socket fallback
 */
async function runPortScan(domain, onProgress) {
  const results = {
    domain,
    targetIPs: [],
    openPorts: [],
    services: [],
    exposedDangerousPorts: [],
    findings: [],
  };

  // Resolve IPs
  onProgress('Resolving target IP addresses...');
  try {
    const ips = await dns.resolve4(domain);
    results.targetIPs = ips;
    onProgress(`Scanning ${ips.length} IP address(es): ${ips.join(', ')}`);
  } catch (e) {
    onProgress(`Could not resolve ${domain}: ${e.message}`);
    return results;
  }

  const targetIP = results.targetIPs[0];
  if (!targetIP) return results;

  // --- nmap scan ---
  if (await isToolAvailable('nmap')) {
    onProgress('Running nmap service scan (top 1000 ports)...');
    try {
      // -sV: version detection, -T4: aggressive timing
      // --top-ports 100: most common ports, -oX -: XML output
      const output = await execCommand(
        `nmap -sV --version-intensity 3 -T4 --top-ports 100 --open --host-timeout 60s -oX - ${targetIP}`,
        120000 // 2 min timeout
      );
      parseNmapXML(output, results);
      onProgress(`nmap found ${results.openPorts.length} open ports`);
    } catch (e) {
      onProgress(`nmap error: ${e.message}. Falling back to basic scan...`);
      await basicPortScan(targetIP, results, onProgress);
    }
  } else {
    onProgress('nmap not found. Running basic TCP port scan...');
    await basicPortScan(targetIP, results, onProgress);
  }

  // --- Analyze for dangerous exposures ---
  results.exposedDangerousPorts = identifyDangerousExposures(results.openPorts);
  results.findings = generatePortFindings(results);

  onProgress('Port scan complete');
  return results;
}

function parseNmapXML(xml, results) {
  // Simple regex-based XML parsing (use xml2js in production)
  const portRegex = /<port protocol="(\w+)" portid="(\d+)">[\s\S]*?<state state="(\w+)"[\s\S]*?(?:<service name="([^"]*)"[^>]*(?:product="([^"]*)")?[^>]*(?:version="([^"]*)")?)?/g;
  let match;
  while ((match = portRegex.exec(xml)) !== null) {
    const [, protocol, portId, state, service, product, version] = match;
    if (state === 'open') {
      results.openPorts.push({
        port: parseInt(portId),
        protocol,
        state,
        service: service || 'unknown',
        product: product || '',
        version: version || '',
        banner: `${product || service || ''} ${version || ''}`.trim(),
      });
    }
  }

  // Extract hostnames
  const hostnameMatch = xml.match(/hostname name="([^"]+)"/g);
  if (hostnameMatch) {
    results.hostnames = hostnameMatch.map(h => h.match(/name="([^"]+)"/)[1]);
  }
}

async function basicPortScan(targetIP, results, onProgress) {
  const net = require('net');
  const COMMON_PORTS = [
    { port: 21, service: 'FTP' },
    { port: 22, service: 'SSH' },
    { port: 23, service: 'Telnet' },
    { port: 25, service: 'SMTP' },
    { port: 53, service: 'DNS' },
    { port: 80, service: 'HTTP' },
    { port: 110, service: 'POP3' },
    { port: 143, service: 'IMAP' },
    { port: 443, service: 'HTTPS' },
    { port: 445, service: 'SMB' },
    { port: 465, service: 'SMTPS' },
    { port: 587, service: 'SMTP/Submission' },
    { port: 993, service: 'IMAPS' },
    { port: 995, service: 'POP3S' },
    { port: 1433, service: 'MSSQL' },
    { port: 3306, service: 'MySQL' },
    { port: 3389, service: 'RDP' },
    { port: 5432, service: 'PostgreSQL' },
    { port: 5900, service: 'VNC' },
    { port: 6379, service: 'Redis' },
    { port: 8080, service: 'HTTP-Alt' },
    { port: 8443, service: 'HTTPS-Alt' },
    { port: 8888, service: 'HTTP-Dev' },
    { port: 9200, service: 'Elasticsearch' },
    { port: 9300, service: 'Elasticsearch-Cluster' },
    { port: 27017, service: 'MongoDB' },
    { port: 6443, service: 'Kubernetes API' },
    { port: 2375, service: 'Docker API (unencrypted)' },
    { port: 2376, service: 'Docker API (TLS)' },
    { port: 5672, service: 'RabbitMQ' },
    { port: 9092, service: 'Kafka' },
    { port: 2181, service: 'Zookeeper' },
    { port: 4848, service: 'GlassFish Admin' },
    { port: 7001, service: 'WebLogic' },
    { port: 8161, service: 'ActiveMQ Web Console' },
  ];

  onProgress(`Scanning ${COMMON_PORTS.length} common ports...`);

  const CONCURRENCY = 50;
  const chunks = [];
  for (let i = 0; i < COMMON_PORTS.length; i += CONCURRENCY) {
    chunks.push(COMMON_PORTS.slice(i, i + CONCURRENCY));
  }

  for (const chunk of chunks) {
    const checks = chunk.map(({ port, service }) => {
      return new Promise((resolve) => {
        const socket = new net.Socket();
        const timeout = 3000;
        let banner = '';

        socket.setTimeout(timeout);
        socket.on('connect', () => {
          results.openPorts.push({ port, protocol: 'tcp', state: 'open', service, banner });
          socket.destroy();
          resolve();
        });
        socket.on('data', (data) => { banner = data.toString().substring(0, 100); });
        socket.on('timeout', () => { socket.destroy(); resolve(); });
        socket.on('error', () => { socket.destroy(); resolve(); });
        socket.connect(port, targetIP);
      });
    });
    await Promise.allSettled(checks);
  }

  onProgress(`Basic scan found ${results.openPorts.length} open ports`);
}

function identifyDangerousExposures(openPorts) {
  const DANGEROUS_PORTS = {
    21: { severity: 'high', reason: 'FTP - plaintext credentials, often exploitable' },
    23: { severity: 'critical', reason: 'Telnet - unencrypted remote access' },
    25: { severity: 'medium', reason: 'SMTP - may allow open relay' },
    445: { severity: 'critical', reason: 'SMB - historically exploited (EternalBlue, etc.)' },
    3389: { severity: 'high', reason: 'RDP - exposed to brute force and exploits' },
    5900: { severity: 'high', reason: 'VNC - often weakly protected' },
    6379: { severity: 'critical', reason: 'Redis - usually no auth by default' },
    9200: { severity: 'high', reason: 'Elasticsearch - may expose data without auth' },
    27017: { severity: 'high', reason: 'MongoDB - may expose data without auth' },
    2375: { severity: 'critical', reason: 'Docker API (unencrypted) - full container takeover' },
    6443: { severity: 'medium', reason: 'Kubernetes API - verify authentication' },
    5432: { severity: 'high', reason: 'PostgreSQL - database directly exposed' },
    3306: { severity: 'high', reason: 'MySQL - database directly exposed' },
    1433: { severity: 'high', reason: 'MSSQL - database directly exposed' },
    8161: { severity: 'high', reason: 'ActiveMQ Web Console - often default credentials' },
    4848: { severity: 'high', reason: 'GlassFish Admin Console - often default credentials' },
    7001: { severity: 'high', reason: 'WebLogic - historically critical vulnerabilities' },
  };

  return openPorts
    .filter(p => DANGEROUS_PORTS[p.port])
    .map(p => ({
      ...p,
      ...DANGEROUS_PORTS[p.port],
    }));
}

function generatePortFindings(results) {
  const findings = [];

  results.exposedDangerousPorts.forEach(port => {
    findings.push({
      id: `PORT-${port.port}`,
      severity: port.severity,
      title: `Dangerous Port Exposed: ${port.port}/${port.service}`,
      description: `Port ${port.port} (${port.service}) is publicly accessible. ${port.reason}`,
      module: 'portScan',
      affected: `${results.targetIPs[0]}:${port.port}`,
      remediation: getPortRemediation(port.port),
    });
  });

  const dbPorts = [3306, 5432, 27017, 6379, 9200, 1433, 5672, 9092];
  const exposedDBs = results.openPorts.filter(p => dbPorts.includes(p.port));
  if (exposedDBs.length > 0) {
    findings.push({
      id: 'PORT-DB-001',
      severity: 'critical',
      title: 'Database Services Publicly Exposed',
      description: `${exposedDBs.length} database service(s) are publicly accessible: ${exposedDBs.map(p => p.service).join(', ')}`,
      module: 'portScan',
      remediation: 'Move database services behind a firewall. Use VPN or bastion host for access.',
    });
  }

  return findings;
}

function getPortRemediation(port) {
  const remediations = {
    21: 'Replace FTP with SFTP or FTPS. Restrict access to known IP ranges.',
    23: 'Disable Telnet immediately. Use SSH for remote access.',
    445: 'Block SMB ports at the firewall perimeter. Apply MS17-010 patches.',
    3389: 'Restrict RDP to VPN-only. Enable NLA. Use jump hosts.',
    6379: 'Add Redis authentication (requirepass). Bind to localhost only.',
    9200: 'Enable Elasticsearch X-Pack security. Restrict access via firewall.',
    27017: 'Enable MongoDB authentication. Bind to localhost or VPN-only.',
    2375: 'Disable the unencrypted Docker API immediately. Use TLS-enabled API only.',
  };
  return remediations[port] || 'Restrict access to this port via firewall rules and ensure proper authentication.';
}

module.exports = { runPortScan };
