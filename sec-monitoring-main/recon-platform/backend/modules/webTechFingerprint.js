/**
 * Module 5: Web Technology Fingerprinting
 * Wappalyzer-style detection via HTTP headers, HTML, JS analysis
 * Uses native fetch (Node 18+) with AbortSignal.timeout for reliability
 */
async function runWebTechFingerprint(domain, onProgress) {
  const results = {
    domain, url: null, technologies: [], cms: null,
    frameworks: [], cdn: null, analytics: [], security: [], findings: [],
  };

  const urls = [`https://${domain}`, `http://${domain}`];
  let response = null;
  let html = '';
  let finalUrl = null;

  onProgress('Fetching main page for technology fingerprinting...');

  for (const url of urls) {
    try {
      response = await fetch(url, {
        redirect: 'follow',
        signal: AbortSignal.timeout(15000),
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36' },
      });
      html = await response.text();
      finalUrl = url;
      results.url = response.url || url;
      break;
    } catch (_) {}
  }

  if (!html) {
    onProgress('Could not fetch page content for fingerprinting');
    return results;
  }

  onProgress('Analyzing HTTP headers...');
  const headers = response ? Object.fromEntries(response.headers.entries()) : {};
  results.technologies.push(...detectFromHeaders(headers));

  onProgress('Analyzing HTML content...');
  results.technologies.push(...detectFromHTML(html));

  onProgress('Analyzing JavaScript patterns...');
  results.technologies.push(...detectFromJS(html));

  onProgress('Inspecting cookies...');
  results.technologies.push(...detectFromCookies(headers));

  onProgress('Checking common paths for CMS detection...');
  results.technologies.push(...await detectCMSPaths(finalUrl));

  // Deduplicate
  const seen = new Set();
  results.technologies = results.technologies.filter(t => {
    const key = `${t.name}:${t.category}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  results.cms = results.technologies.find(t => t.category === 'CMS') || null;
  results.frameworks = results.technologies.filter(t => ['Frontend Framework', 'Backend Framework', 'Web Framework'].includes(t.category));
  results.cdn = results.technologies.find(t => t.category === 'CDN') || null;
  results.analytics = results.technologies.filter(t => t.category === 'Analytics');

  onProgress(`Detected ${results.technologies.length} technologies`);
  results.findings = generateWebTechFindings(results, headers);

  onProgress('Web technology fingerprinting complete');
  return results;
}

function detectFromHeaders(headers) {
  const techs = [];
  const sigs = [
    { header: 'server', pattern: /nginx/i, name: 'Nginx', category: 'Web Server' },
    { header: 'server', pattern: /apache/i, name: 'Apache', category: 'Web Server' },
    { header: 'server', pattern: /Microsoft-IIS/i, name: 'IIS', category: 'Web Server' },
    { header: 'server', pattern: /openresty/i, name: 'OpenResty', category: 'Web Server' },
    { header: 'server', pattern: /cloudflare/i, name: 'Cloudflare', category: 'CDN' },
    { header: 'server', pattern: /AmazonS3/i, name: 'Amazon S3', category: 'Cloud Storage' },
    { header: 'via', pattern: /cloudfront/i, name: 'Amazon CloudFront', category: 'CDN' },
    { header: 'x-cdn', pattern: /akamai/i, name: 'Akamai', category: 'CDN' },
    { header: 'x-fastly-request-id', pattern: /.+/, name: 'Fastly', category: 'CDN' },
    { header: 'cf-ray', pattern: /.+/, name: 'Cloudflare', category: 'CDN' },
    { header: 'x-amz-cf-id', pattern: /.+/, name: 'Amazon CloudFront', category: 'CDN' },
    { header: 'x-powered-by', pattern: /php/i, name: 'PHP', category: 'Language' },
    { header: 'x-powered-by', pattern: /asp\.net/i, name: 'ASP.NET', category: 'Backend Framework' },
    { header: 'x-powered-by', pattern: /express/i, name: 'Express.js', category: 'Backend Framework' },
    { header: 'x-powered-by', pattern: /next\.js/i, name: 'Next.js', category: 'Frontend Framework' },
    { header: 'x-powered-by', pattern: /rails/i, name: 'Ruby on Rails', category: 'Backend Framework' },
    { header: 'x-sucuri-id', pattern: /.+/, name: 'Sucuri', category: 'WAF' },
    { header: 'x-waf-event-info', pattern: /.+/, name: 'Incapsula', category: 'WAF' },
    { header: 'x-cache', pattern: /cloudfront/i, name: 'Amazon CloudFront', category: 'CDN' },
  ];
  sigs.forEach(sig => {
    const val = headers[sig.header] || '';
    if (sig.pattern.test(val)) {
      techs.push({ name: sig.name, category: sig.category, confidence: 'high', source: 'headers', evidence: `${sig.header}: ${val.substring(0, 80)}` });
    }
  });
  return techs;
}

function detectFromHTML(html) {
  const techs = [];
  const sigs = [
    { pattern: /react(?:dom|\.createElement|ReactDOM)/i, name: 'React', category: 'Frontend Framework' },
    { pattern: /angular(?:\.min\.js|\/core|ng-app|ng-controller)/i, name: 'Angular', category: 'Frontend Framework' },
    { pattern: /vue(?:\.js|\.min\.js|v-app|v-bind|v-model)/i, name: 'Vue.js', category: 'Frontend Framework' },
    { pattern: /svelte/i, name: 'Svelte', category: 'Frontend Framework' },
    { pattern: /__NEXT_DATA__|_next\/static/i, name: 'Next.js', category: 'Frontend Framework' },
    { pattern: /nuxt(?:\.js|\/dist|__nuxt)/i, name: 'Nuxt.js', category: 'Frontend Framework' },
    { pattern: /wp-content|wp-includes|wordpress/i, name: 'WordPress', category: 'CMS' },
    { pattern: /drupal\.settings|sites\/all\/modules|drupal/i, name: 'Drupal', category: 'CMS' },
    { pattern: /joomla|\/components\/com_/i, name: 'Joomla', category: 'CMS' },
    { pattern: /magento|mage\/cookies|var Mage/i, name: 'Magento', category: 'CMS' },
    { pattern: /shopify|myshopify\.com|Shopify\.theme/i, name: 'Shopify', category: 'E-commerce' },
    { pattern: /ghost\//i, name: 'Ghost', category: 'CMS' },
    { pattern: /squarespace/i, name: 'Squarespace', category: 'CMS' },
    { pattern: /wix\.com|wixsite\.com/i, name: 'Wix', category: 'CMS' },
    { pattern: /webflow/i, name: 'Webflow', category: 'CMS' },
    { pattern: /laravel|csrf_token.*laravel/i, name: 'Laravel', category: 'Backend Framework' },
    { pattern: /django|csrfmiddlewaretoken/i, name: 'Django', category: 'Backend Framework' },
    { pattern: /rails-csrf|data-authenticity-token/i, name: 'Ruby on Rails', category: 'Backend Framework' },
    { pattern: /google-analytics\.com|GoogleAnalytics|ga\('create'/i, name: 'Google Analytics', category: 'Analytics' },
    { pattern: /googletagmanager\.com\/gtm\.js/i, name: 'Google Tag Manager', category: 'Analytics' },
    { pattern: /segment\.com|analytics\.js/i, name: 'Segment', category: 'Analytics' },
    { pattern: /mixpanel/i, name: 'Mixpanel', category: 'Analytics' },
    { pattern: /hotjar/i, name: 'Hotjar', category: 'Analytics' },
    { pattern: /intercom/i, name: 'Intercom', category: 'Live Chat' },
    { pattern: /zendesk/i, name: 'Zendesk', category: 'Customer Support' },
    { pattern: /hubspot/i, name: 'HubSpot', category: 'Marketing' },
    { pattern: /bootstrap(?:\.min)?\.css|bootstrap(?:\.min)?\.js/i, name: 'Bootstrap', category: 'UI Library' },
    { pattern: /tailwindcss|tailwind\.min/i, name: 'Tailwind CSS', category: 'UI Library' },
    { pattern: /materialize(?:-css)?/i, name: 'Materialize CSS', category: 'UI Library' },
    { pattern: /jquery(?:\.min)?\.js|jQuery\s*=/i, name: 'jQuery', category: 'JavaScript Library' },
    { pattern: /amazonaws\.com/i, name: 'Amazon AWS', category: 'Cloud' },
    { pattern: /storage\.googleapis\.com/i, name: 'Google Cloud Storage', category: 'Cloud' },
    { pattern: /azurewebsites\.net|blob\.core\.windows\.net/i, name: 'Microsoft Azure', category: 'Cloud' },
  ];
  sigs.forEach(sig => {
    if (sig.pattern.test(html)) {
      const m = html.match(sig.pattern);
      techs.push({ name: sig.name, category: sig.category, confidence: 'medium', source: 'html', evidence: m ? m[0].substring(0, 60) : null });
    }
  });
  return techs;
}

function detectFromJS(html) {
  const techs = [];
  const sigs = [
    { pattern: /window\.__REDUX_STORE__|createStore|redux/i, name: 'Redux', category: 'JavaScript Library' },
    { pattern: /window\.__APOLLO_STATE__|ApolloClient/i, name: 'Apollo GraphQL', category: 'API' },
    { pattern: /window\.Stripe|stripe\.com\/v3/i, name: 'Stripe', category: 'Payment' },
    { pattern: /firebase|firebaseapp\.com/i, name: 'Firebase', category: 'Cloud' },
    { pattern: /supabase/i, name: 'Supabase', category: 'Backend as a Service' },
    { pattern: /vercel/i, name: 'Vercel', category: 'Hosting' },
    { pattern: /netlify/i, name: 'Netlify', category: 'Hosting' },
    { pattern: /webpack(?:Jsonp|__webpack_require__)/i, name: 'Webpack', category: 'Build Tool' },
    { pattern: /vite\/client|@vite/i, name: 'Vite', category: 'Build Tool' },
    { pattern: /sentry\.|@sentry\//i, name: 'Sentry', category: 'Error Tracking' },
    { pattern: /datadog/i, name: 'Datadog', category: 'Monitoring' },
    { pattern: /newrelic/i, name: 'New Relic', category: 'Monitoring' },
  ];
  sigs.forEach(sig => {
    if (sig.pattern.test(html)) {
      const m = html.match(sig.pattern);
      techs.push({ name: sig.name, category: sig.category, confidence: 'medium', source: 'javascript', evidence: m ? m[0].substring(0, 60) : null });
    }
  });
  return techs;
}

function detectFromCookies(headers) {
  const techs = [];
  const cookies = headers['set-cookie'] || '';
  const cookieStr = Array.isArray(cookies) ? cookies.join('; ') : cookies;
  const sigs = [
    { pattern: /PHPSESSID/i, name: 'PHP', category: 'Language' },
    { pattern: /ASP\.NET_SessionId|\.ASPXAUTH/i, name: 'ASP.NET', category: 'Backend Framework' },
    { pattern: /JSESSIONID/i, name: 'Java (Servlet)', category: 'Backend Framework' },
    { pattern: /laravel_session/i, name: 'Laravel', category: 'Backend Framework' },
    { pattern: /wordpress_|wp-settings/i, name: 'WordPress', category: 'CMS' },
    { pattern: /__cfduid|cf_clearance/i, name: 'Cloudflare', category: 'CDN' },
    { pattern: /_ga(?:_\w+)?=/i, name: 'Google Analytics', category: 'Analytics' },
    { pattern: /intercom-session/i, name: 'Intercom', category: 'Live Chat' },
    { pattern: /ajs_user_id|ajs_anonymous_id/i, name: 'Segment', category: 'Analytics' },
  ];
  sigs.forEach(sig => {
    if (sig.pattern.test(cookieStr)) {
      techs.push({ name: sig.name, category: sig.category, confidence: 'high', source: 'cookies' });
    }
  });
  return techs;
}

async function detectCMSPaths(baseUrl) {
  if (!baseUrl) return [];
  const techs = [];
  const paths = [
    { path: '/wp-login.php', name: 'WordPress', category: 'CMS' },
    { path: '/wp-admin/', name: 'WordPress', category: 'CMS' },
    { path: '/xmlrpc.php', name: 'WordPress XML-RPC', category: 'CMS' },
    { path: '/administrator/', name: 'Joomla', category: 'CMS' },
    { path: '/user/login', name: 'Drupal', category: 'CMS' },
    { path: '/robots.txt', name: 'robots.txt', category: 'Info Disclosure' },
    { path: '/.git/', name: 'Git Repository', category: 'Security Risk' },
    { path: '/phpmyadmin/', name: 'phpMyAdmin', category: 'Database Admin' },
    { path: '/adminer.php', name: 'Adminer', category: 'Database Admin' },
    { path: '/.env', name: 'Environment File', category: 'Security Risk' },
    { path: '/server-status', name: 'Apache Server Status', category: 'Info Disclosure' },
    { path: '/actuator', name: 'Spring Boot Actuator', category: 'Backend Framework' },
    { path: '/actuator/health', name: 'Spring Boot Actuator', category: 'Backend Framework' },
    { path: '/_next/static/', name: 'Next.js', category: 'Frontend Framework' },
    { path: '/nuxt/', name: 'Nuxt.js', category: 'Frontend Framework' },
    { path: '/graphql', name: 'GraphQL', category: 'API' },
    { path: '/api/graphql', name: 'GraphQL', category: 'API' },
  ];

  const checks = paths.map(async ({ path, name, category }) => {
    try {
      const url = baseUrl + path;
      const res = await fetch(url, {
        method: 'HEAD',
        signal: AbortSignal.timeout(5000),
        redirect: 'manual',
      });
      if (res.status < 400 || res.status === 403) {
        techs.push({ name, category, confidence: 'high', source: 'path_probe', evidence: `${path} → HTTP ${res.status}`, url });
      }
    } catch (_) {}
  });

  await Promise.allSettled(checks);
  return techs;
}

function generateWebTechFindings(results, headers) {
  const findings = [];
  results.technologies.filter(t => ['Security Risk', 'Database Admin', 'Info Disclosure'].includes(t.category)).forEach(tech => {
    const severity = ['Security Risk', 'Database Admin'].includes(tech.category) ? 'critical' : 'medium';
    findings.push({
      id: `WEB-${tech.name.replace(/\s+/g, '-').toUpperCase()}`, severity,
      title: `Exposed: ${tech.name}`,
      description: `${tech.name} was detected at ${tech.url || 'the target'}. ${tech.evidence || ''}`,
      module: 'webTechFingerprint', affected: tech.url,
      remediation: getWebTechRemediation(tech.name),
    });
  });

  if (results.cms?.name === 'WordPress') {
    findings.push({
      id: 'WEB-WP-001', severity: 'medium', title: 'WordPress CMS Detected',
      description: 'WordPress detected. Ensure it is up to date and hardened.',
      module: 'webTechFingerprint',
      remediation: 'Disable XML-RPC if not needed, restrict wp-admin by IP, install a security plugin.',
    });
  }

  if (!headers['strict-transport-security']) {
    findings.push({
      id: 'WEB-HSTS', severity: 'medium', title: 'HSTS Not Enforced',
      description: 'HTTP Strict Transport Security (HSTS) header is missing.',
      module: 'webTechFingerprint',
      remediation: 'Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
    });
  }

  if (headers['x-powered-by']) {
    findings.push({
      id: 'WEB-INFO-LEAK', severity: 'low',
      title: 'Technology Stack Disclosed via X-Powered-By',
      description: `X-Powered-By header reveals: ${headers['x-powered-by']}`,
      module: 'webTechFingerprint', remediation: 'Remove or obscure the X-Powered-By header.',
    });
  }

  return findings;
}

function getWebTechRemediation(name) {
  const map = {
    'Environment File': 'Remove .env from web root immediately. Add to .gitignore. Rotate all exposed secrets.',
    'Git Repository': 'Remove .git directory from web root. Block access at web server level.',
    'phpMyAdmin': 'Restrict phpMyAdmin to specific IPs or internal network only.',
    'Adminer': 'Remove Adminer from production server or restrict by IP.',
    'Apache Server Status': 'Disable mod_status or restrict to localhost only.',
    'Spring Boot Actuator': 'Secure actuator endpoints with authentication. Disable sensitive endpoints in production.',
    'WordPress XML-RPC': 'Disable XML-RPC if not required.',
  };
  return map[name] || 'Restrict access to this resource or remove it from public exposure.';
}

module.exports = { runWebTechFingerprint };
