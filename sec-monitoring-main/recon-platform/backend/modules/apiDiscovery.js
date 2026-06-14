'use strict';
/**
 * apiDiscovery.js — Public API Endpoint Discovery
 *
 * Discovers public API endpoints exposed by a target website using:
 *  1. Swagger / OpenAPI spec file probing (20+ common paths)
 *  2. GraphQL endpoint detection + introspection
 *  3. Common REST API path probing (/api, /api/v1, /api/v2, etc.)
 *  4. JavaScript file parsing (extracts endpoints from fetch/axios calls)
 *  5. robots.txt & sitemap.xml analysis
 *  6. HTML form action URL extraction
 *  7. HTTP Link / API-related response header analysis
 *  8. WSDL/SOAP endpoint detection
 *  9. JSON:API, OData, HATEOAS pattern detection
 */

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';

// ── Safe fetch helper ─────────────────────────────────────────────────────────
async function safeFetch(url, opts = {}) {
  try {
    const res = await fetch(url, {
      redirect:  'follow',
      signal:    AbortSignal.timeout(opts.timeout || 8000),
      headers:   { 'User-Agent': UA, 'Accept': '*/*', ...(opts.headers || {}) },
    });
    const body = await res.text().catch(() => '');
    return { ok: res.ok, status: res.status, body, headers: Object.fromEntries(res.headers.entries()) };
  } catch (_) {
    return { ok: false, status: 0, body: '', headers: {} };
  }
}

// Try to parse body as JSON safely
function tryJSON(body) {
  try { return JSON.parse(body); } catch (_) { return null; }
}

// Detect content-type
function isJSON(headers, body) {
  const ct = headers['content-type'] || '';
  if (ct.includes('json')) return true;
  const b = body.trim();
  return (b.startsWith('{') || b.startsWith('[')) && b.length < 2_000_000;
}

function isYAML(headers, body) {
  const ct = headers['content-type'] || '';
  return ct.includes('yaml') || ct.includes('x-yaml') || body.trim().startsWith('openapi:') || body.trim().startsWith('swagger:');
}

// ── 1. OpenAPI / Swagger Probing ──────────────────────────────────────────────
const SWAGGER_PATHS = [
  '/swagger.json', '/swagger/v1/swagger.json', '/swagger/v2/swagger.json',
  '/swagger/v3/swagger.json', '/api-docs', '/api-docs.json', '/api/swagger.json',
  '/api/swagger', '/api/docs', '/api/v1/swagger.json', '/api/v2/swagger.json',
  '/api/v3/swagger.json', '/openapi.json', '/openapi.yaml', '/openapi/v1/openapi.json',
  '/v1/api-docs', '/v2/api-docs', '/v3/api-docs', '/docs/api-docs.json',
  '/api/openapi.json', '/api/openapi.yaml', '/swagger-ui/swagger.json',
  '/api/swagger-ui.json', '/swagger/index.html', '/api/swagger-ui',
  '/.well-known/openapi.json', '/api/schema', '/api/schema.json',
  '/api/spec', '/api/spec.json', '/rest/api-docs', '/rest/swagger.json',
];

async function probeSwagger(baseUrl, onProgress) {
  const found = [];
  onProgress('API Discovery: probing Swagger/OpenAPI spec endpoints...');

  await Promise.allSettled(
    SWAGGER_PATHS.map(async (path) => {
      const r = await safeFetch(baseUrl + path, { timeout: 5000 });
      if (!r.ok && r.status !== 200) return;

      const body = r.body;
      if (!body || body.length < 10) return;

      // Stage 1: Quick keyword scan — must have a version-value pair for openapi/swagger
      // Matches:  "openapi": "3.0.1"  |  openapi: "3.0.1"  |  swagger: "2.0"
      const hasVersionDeclaration =
        /["']?openapi["']?\s*:\s*["']?\d/i.test(body) ||
        /["']?swagger["']?\s*:\s*["']?\d/i.test(body);
      if (!hasVersionDeclaration) return;

      // Stage 2: Must also declare paths or endpoints
      const hasPaths = body.includes('"paths"') || body.includes('paths:');
      if (!hasPaths) return;

      const spec       = tryJSON(body);
      const specVersion = spec?.openapi || spec?.swagger || 'unknown';
      // Validate specVersion is a real OpenAPI version (2.x or 3.x)
      if (specVersion !== 'unknown' && !/^[23]\.\d/.test(specVersion)) return;

      const title     = spec?.info?.title || 'API Spec';
      const version   = spec?.info?.version || '?';
      const endpoints = spec?.paths ? Object.keys(spec.paths) : [];

      found.push({
        type:       'openapi',
        url:        baseUrl + path,
        path,
        specVersion,
        title,
        version,
        endpoints,
        endpointCount: endpoints.length,
        description: `${title} v${version} — ${endpoints.length} endpoint(s) discovered`,
      });
    })
  );

  return found;
}

// ── 2. GraphQL Detection ──────────────────────────────────────────────────────
const GRAPHQL_PATHS = [
  '/graphql', '/graphql/v1', '/graphql/v2', '/gql', '/api/graphql',
  '/api/gql', '/query', '/graph', '/graphiql', '/playground',
];

const INTROSPECTION_QUERY = JSON.stringify({
  query: `{__schema{types{name kind fields{name type{name kind}}}queryType{name}mutationType{name}}}`,
});

async function probeGraphQL(baseUrl, onProgress) {
  const found = [];
  onProgress('API Discovery: probing GraphQL endpoints...');

  await Promise.allSettled(
    GRAPHQL_PATHS.map(async (path) => {
      const url = baseUrl + path;

      // Try POST with introspection
      let r;
      try {
        r = await fetch(url, {
          method:  'POST',
          headers: { 'Content-Type': 'application/json', 'User-Agent': UA },
          body:    INTROSPECTION_QUERY,
          signal:  AbortSignal.timeout(7000),
        });
      } catch (_) { return; }

      const body = await r.text().catch(() => '');
      const json = tryJSON(body);

      // Check if it looks like a GraphQL response
      const isGQL = json?.data?.__schema || body.includes('"__schema"')
        || body.includes('"data"') && body.includes('queryType')
        || (r.status === 400 && body.includes('GraphQL'))
        || (r.status === 200 && body.includes('"errors"') && body.includes('graphql'));

      if (!isGQL) return;

      // Extract type names from schema introspection
      const types = (json?.data?.__schema?.types || [])
        .filter(t => !t.name.startsWith('__'))
        .map(t => t.name);

      const queryType  = json?.data?.__schema?.queryType?.name  || 'Query';
      const mutType    = json?.data?.__schema?.mutationType?.name || null;

      found.push({
        type:        'graphql',
        url,
        path,
        queryType,
        mutationType:  mutType,
        types:         types.slice(0, 50),
        typeCount:     types.length,
        introspection: types.length > 0,
        description:   `GraphQL endpoint${types.length > 0 ? ` — ${types.length} types` : ''} (introspection ${types.length > 0 ? 'enabled' : 'disabled'})`,
      });
    })
  );

  return found;
}

// ── 3. Common REST API Path Probing ──────────────────────────────────────────
const REST_API_PATHS = [
  '/api', '/api/v1', '/api/v2', '/api/v3', '/api/v4', '/api/v5',
  '/api/v1.0', '/api/v2.0', '/api/v3.0',
  '/rest', '/rest/v1', '/rest/v2', '/rest/api',
  '/service', '/services', '/webservice', '/ws',
  '/json', '/data', '/feed', '/feeds',
  '/public/api', '/api/public', '/open/api',
  '/api/external', '/external/api',
  '/api/resources', '/resources',
  '/v1', '/v2', '/v3', '/v4',
  '/_api', '/__api', '/internal/api',
  '/api/health', '/health', '/healthz', '/ping', '/status',
  '/api/status', '/api/ping', '/api/version',
  '/api/me', '/api/users', '/api/user',
  '/api/products', '/api/items', '/api/search',
];

// Signals that indicate an actual API response (not just a landing page)
function isApiResponse(status, headers, body) {
  const ct = headers['content-type'] || '';
  // Must be a 2xx response to be considered a live API endpoint
  if (status < 200 || status >= 300) return false;
  if (ct.includes('json')) {
    // JSON content-type is a strong signal, but body must have meaningful content
    const t = body.trim();
    if (t.length < 2) return false;
    // Reject trivially empty JSON: {}, [], "", 0, null, true/false
    if (/^(\{\s*\}|\[\s*\]|null|true|false|0|".*")$/i.test(t)) return false;
    return true;
  }
  if (ct.includes('xml') && (body.includes('<api') || body.includes('<response') || body.includes('<resource'))) return true;
  if (!body || body.length < 2) return false;
  const t = body.trim();
  // JSON object or array with actual content
  if ((t.startsWith('{') || t.startsWith('[')) && t.length > 20 && t.length < 500000) {
    // Must have at least one key to be a meaningful API response
    if (t.startsWith('{') && !t.includes(':')) return false;
    return true;
  }
  return false;
}

async function probeRestPaths(baseUrl, onProgress) {
  const found = [];
  onProgress('API Discovery: probing common REST API paths...');

  await Promise.allSettled(
    REST_API_PATHS.map(async (path) => {
      const r = await safeFetch(baseUrl + path, { timeout: 5000 });
      if (r.status === 0) return;
      // Skip 404, 500 unless it returns JSON (some APIs return JSON errors)
      if (r.status === 404 && !isApiResponse(r.status, r.headers, r.body)) return;
      if (r.status >= 500) return;

      if (!isApiResponse(r.status, r.headers, r.body)) return;

      const json    = tryJSON(r.body);
      const ct      = r.headers['content-type'] || 'application/json';
      const isAuth  = r.status === 401 || r.status === 403;
      const snippet = r.body.slice(0, 200).replace(/\s+/g, ' ').trim();

      found.push({
        type:          'rest',
        url:           baseUrl + path,
        path,
        httpStatus:    r.status,
        contentType:   ct,
        requiresAuth:  isAuth,
        responseKeys:  json && typeof json === 'object' && !Array.isArray(json) ? Object.keys(json).slice(0, 10) : [],
        snippet,
        description:   `REST endpoint — HTTP ${r.status}${isAuth ? ' (auth required)' : ''}`,
      });
    })
  );

  return found;
}

// ── 4. JS File Parsing — Extract API Calls ────────────────────────────────────

// Patterns to extract API base URLs and endpoints from JS code
const JS_API_PATTERNS = [
  // fetch('/api/...') or fetch("https://api...")
  /fetch\s*\(\s*[`'"]((?:https?:\/\/[^`'"]*|\/[a-zA-Z0-9/_\-\.?=&{}`]*(?:api|v\d|rest|gql|graphql|service|endpoint)[a-zA-Z0-9/_\-\.?=&{}]*)[`'"]\s*\))/gi,
  // axios.get('/api/...') or axios.post(...)
  /axios\s*\.\s*(?:get|post|put|patch|delete|head)\s*\(\s*[`'"](\/[^`'"]{3,100})[`'"]/gi,
  // baseURL: '/api' or baseUrl: 'https://...'
  /(?:baseURL|baseUrl|apiUrl|API_URL|apiBase|base_url)\s*[:=]\s*[`'"]((?:https?:\/\/[^`'"]{5,100}|\/[a-zA-Z][^`'"]{2,80}))[`'"]/gi,
  // this.$http.get('/...') — Vue
  /\$http\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*[`'"](\/[^`'"]{3,80})[`'"]/gi,
  // XMLHttpRequest.open('GET', '/...')
  /\.open\s*\(\s*['"](?:GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*[`'"](\/[^`'"]{3,80})[`'"]/gi,
  // url: '/api/...' in objects
  /\burl\s*:\s*[`'"](\/api[^`'"]{0,80})[`'"]/gi,
  // endpoints in const/let/var declarations
  /(?:const|let|var)\s+\w*(?:[Ee]ndpoint|[Pp]ath|[Rr]oute|[Uu]rl)\s*=\s*[`'"](\/[^`'"]{3,80})[`'"]/gi,
];

async function parseJSFiles(baseUrl, html, onProgress) {
  const endpoints = new Set();
  const scriptUrls = [];

  // Extract all <script src="..."> URLs from the page
  const srcRe = /<script[^>]+src\s*=\s*["']([^"']+\.js[^"']*?)["']/gi;
  let m;
  while ((m = srcRe.exec(html)) !== null) {
    let src = m[1].split('?')[0];
    if (src.startsWith('//')) src = 'https:' + src;
    else if (src.startsWith('/')) src = baseUrl.replace(/\/$/, '') + src;
    else if (!src.startsWith('http')) src = baseUrl + '/' + src;
    // Only scan same-origin scripts
    try {
      const srcHost = new URL(src).hostname;
      const baseHost = new URL(baseUrl).hostname;
      if (srcHost !== baseHost) continue; // skip CDN scripts
    } catch (_) {}
    scriptUrls.push(src);
  }

  // Also extract inline <script> content
  const inlineRe = /<script(?:[^>]*)>([\s\S]*?)<\/script>/gi;
  const inlineScripts = [];
  while ((m = inlineRe.exec(html)) !== null) {
    if (m[1] && m[1].length > 50) inlineScripts.push(m[1]);
  }

  // Parse inline scripts immediately
  for (const code of inlineScripts) {
    for (const pat of JS_API_PATTERNS) {
      pat.lastIndex = 0;
      let pm;
      while ((pm = pat.exec(code)) !== null) {
        const ep = pm[1];
        if (ep && ep.length > 2 && ep.length < 200) endpoints.add(ep);
      }
    }
  }

  const unique = [...new Set(scriptUrls)].slice(0, 15);
  if (unique.length > 0) onProgress(`API Discovery: parsing ${unique.length} JavaScript files for API calls...`);

  await Promise.allSettled(unique.map(async (scriptUrl) => {
    const r = await safeFetch(scriptUrl, { timeout: 8000 });
    if (!r.ok || !r.body) return;

    const code = r.body;
    for (const pat of JS_API_PATTERNS) {
      pat.lastIndex = 0;
      let pm;
      while ((pm = pat.exec(code)) !== null) {
        const ep = pm[1];
        if (ep && ep.length > 2 && ep.length < 200) endpoints.add(ep);
      }
    }
  }));

  // Filter to unique API-looking endpoints only
  const apiEndpoints = [...endpoints].filter(ep => {
    const lower = ep.toLowerCase();
    return (
      lower.includes('/api') || lower.includes('/v1') || lower.includes('/v2') ||
      lower.includes('/v3') || lower.includes('/rest') || lower.includes('/gql') ||
      lower.includes('/graphql') || lower.includes('/service') || lower.includes('apiurl') ||
      ep.startsWith('http')
    );
  });

  return [...new Set(apiEndpoints)].sort().slice(0, 100);
}

// ── 5. Robots.txt / Sitemap Analysis ─────────────────────────────────────────
async function checkRobotsAndSitemap(baseUrl, onProgress) {
  const apiPaths = [];
  onProgress('API Discovery: analyzing robots.txt and sitemap...');

  // robots.txt
  const robots = await safeFetch(baseUrl + '/robots.txt', { timeout: 5000 });
  if (robots.ok && robots.body) {
    const lines = robots.body.split('\n');
    for (const line of lines) {
      const m = line.match(/^(?:Allow|Disallow):\s*(.+)/i);
      if (m) {
        const p = m[1].trim();
        const lower = p.toLowerCase();
        if (lower.includes('/api') || lower.includes('/rest') || lower.includes('/graphql')
          || lower.includes('/service') || lower.includes('/v1') || lower.includes('/v2')) {
          apiPaths.push({ source: 'robots.txt', path: p });
        }
      }
    }
  }

  // sitemap.xml
  const sitemap = await safeFetch(baseUrl + '/sitemap.xml', { timeout: 5000 });
  if (sitemap.ok && sitemap.body) {
    const locs = [...sitemap.body.matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => m[1]);
    for (const loc of locs) {
      try {
        const u = new URL(loc);
        const lower = u.pathname.toLowerCase();
        if (lower.includes('/api') || lower.includes('/rest') || lower.includes('/service')) {
          apiPaths.push({ source: 'sitemap.xml', path: u.pathname });
        }
      } catch (_) {}
    }
  }

  return apiPaths;
}

// ── 6. HTML Form Actions ──────────────────────────────────────────────────────
function parseFormActions(html) {
  const endpoints = new Set();
  const re = /<form[^>]+action\s*=\s*["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const action = m[1].trim();
    if (action && !action.startsWith('#') && action.length < 200) {
      endpoints.add(action);
    }
  }
  return [...endpoints];
}

// ── 7. Response Header Analysis ───────────────────────────────────────────────
function parseApiHeaders(headers) {
  const signals = [];
  const link = headers['link'] || '';
  // Link: <https://api.example.com>; rel="api"
  const linkMatches = [...link.matchAll(/<([^>]+)>\s*;\s*rel="([^"]+)"/g)];
  for (const m of linkMatches) {
    signals.push({ header: 'Link', url: m[1], rel: m[2] });
  }

  // X-API-Version, X-API-Deprecated, X-RateLimit (strong API signal)
  for (const [k, v] of Object.entries(headers)) {
    const kl = k.toLowerCase();
    if (kl.includes('api') || kl.includes('rate-limit') || kl.includes('ratelimit')) {
      signals.push({ header: k, value: v });
    }
  }
  return signals;
}

// ── 8. WSDL / SOAP Detection ──────────────────────────────────────────────────
const WSDL_PATHS = [
  '/?wsdl', '/service.asmx?wsdl', '/api.asmx?wsdl',
  '/ws?wsdl', '/webservice?wsdl', '/soap?wsdl', '/WS.asmx?wsdl',
  '/api/soap', '/soap/v1', '/soap',
];

async function probeWSDL(baseUrl, onProgress) {
  const found = [];
  onProgress('API Discovery: checking WSDL/SOAP endpoints...');

  await Promise.allSettled(
    WSDL_PATHS.map(async (path) => {
      const r = await safeFetch(baseUrl + path, { timeout: 5000 });
      if (!r.ok && r.status !== 200) return;
      const body = r.body;
      if (!body) return;

      const isWSDL = body.includes('<wsdl:') || body.includes('<definitions ') || body.includes('xmlns:wsdl');
      const isSOAP = body.includes('<soap:') || body.includes('SOAPAction') || body.includes('xmlns:soap');

      if (isWSDL || isSOAP) {
        // Extract service names from WSDL
        const services = [...body.matchAll(/name="([^"]+)"[^>]*>/g)].map(m => m[1]).slice(0, 10);
        found.push({
          type:        'wsdl',
          url:         baseUrl + path,
          path,
          isSOAP,
          isWSDL,
          services,
          description: `WSDL/SOAP service endpoint`,
        });
      }
    })
  );

  return found;
}

// ── 9. Well-known / API discovery endpoints ───────────────────────────────────
const WELL_KNOWN_PATHS = [
  '/.well-known/api', '/.well-known/openapi', '/.well-known/schema',
  '/api/discovery', '/discovery', '/api-catalog', '/apis',
  '/.well-known/oauth-authorization-server', '/.well-known/openid-configuration',
];

async function probeWellKnown(baseUrl, onProgress) {
  const found = [];
  await Promise.allSettled(
    WELL_KNOWN_PATHS.map(async (path) => {
      const r = await safeFetch(baseUrl + path, { timeout: 5000 });
      if (!r.ok || !r.body) return;
      if (!isJSON(r.headers, r.body)) return;
      const json = tryJSON(r.body);
      if (!json) return;
      found.push({
        type:        'well-known',
        url:         baseUrl + path,
        path,
        content:     json,
        description: `Well-known API discovery endpoint`,
      });
    })
  );
  return found;
}

// ── Main Export ───────────────────────────────────────────────────────────────
async function runAPIDiscovery(domain, onProgress) {
  const results = {
    domain,
    openapi:      [],
    graphql:      [],
    rest:         [],
    wsdl:         [],
    wellKnown:    [],
    jsEndpoints:  [],
    robotsPaths:  [],
    formActions:  [],
    apiHeaders:   [],
    findings:     [],
    summary: {
      total:              0,
      openApiSpecs:       0,
      graphqlEndpoints:   0,
      restEndpoints:      0,
      wsdlEndpoints:      0,
      jsExtractedEndpoints: 0,
    },
  };

  onProgress('API Discovery: starting endpoint enumeration...');

  // Fetch the base page first
  const baseUrl  = `https://${domain}`;
  const baseUrl2 = `http://${domain}`;
  let baseR = await safeFetch(baseUrl, { timeout: 10000 });
  if (!baseR.ok && baseR.status === 0) baseR = await safeFetch(baseUrl2, { timeout: 10000 });
  const finalBase = (baseR.ok || baseR.status > 0) ? baseUrl : baseUrl2;

  if (!baseR.body) {
    onProgress('API Discovery: target unreachable');
    return results;
  }

  const html         = baseR.body;
  const baseHeaders  = baseR.headers;

  // Run all discovery techniques in parallel batches
  const [
    swaggerFound,
    graphqlFound,
    restFound,
    wsdlFound,
    wellKnownFound,
    jsEndpoints,
    robotsPaths,
  ] = await Promise.all([
    probeSwagger(finalBase, onProgress),
    probeGraphQL(finalBase, onProgress),
    probeRestPaths(finalBase, onProgress),
    probeWSDL(finalBase, onProgress),
    probeWellKnown(finalBase, onProgress),
    parseJSFiles(finalBase, html, onProgress),
    checkRobotsAndSitemap(finalBase, onProgress),
  ]);

  results.openapi      = swaggerFound;
  results.graphql      = graphqlFound;
  results.rest         = restFound;
  results.wsdl         = wsdlFound;
  results.wellKnown    = wellKnownFound;
  results.jsEndpoints  = jsEndpoints;
  results.robotsPaths  = robotsPaths;
  results.formActions  = parseFormActions(html);
  results.apiHeaders   = parseApiHeaders(baseHeaders);

  // Update summary
  results.summary.openApiSpecs           = swaggerFound.length;
  results.summary.graphqlEndpoints       = graphqlFound.length;
  results.summary.restEndpoints          = restFound.length;
  results.summary.wsdlEndpoints          = wsdlFound.length;
  results.summary.jsExtractedEndpoints   = jsEndpoints.length;
  results.summary.total = swaggerFound.length + graphqlFound.length + restFound.length
    + wsdlFound.length + wellKnownFound.length;

  // Build findings for the main findings aggregation
  for (const spec of swaggerFound) {
    results.findings.push({
      id:          `API-OPENAPI-${spec.path.replace(/\//g, '-')}`,
      severity:    'info',
      title:       `Public OpenAPI Spec Exposed: ${spec.title}`,
      description: `Found Swagger/OpenAPI specification at ${spec.url}. API: "${spec.title}" v${spec.version}, ${spec.endpointCount} endpoint(s) documented. Version: ${spec.specVersion}`,
      module:      'apiDiscovery',
      affected:    spec.url,
      remediation: 'Ensure this spec does not expose sensitive internal endpoints. Consider requiring authentication or restricting access to spec files in production.',
      endpoints:   spec.endpoints,
    });
  }

  for (const gql of graphqlFound) {
    const introspMsg = gql.introspection
      ? `Introspection is ENABLED — full schema exposed (${gql.typeCount} types).`
      : 'Introspection appears disabled.';
    results.findings.push({
      id:          `API-GRAPHQL-${gql.path.replace(/\//g, '-')}`,
      severity:    gql.introspection ? 'medium' : 'info',
      title:       `GraphQL Endpoint Detected: ${gql.url}`,
      description: `GraphQL API found at ${gql.url}. ${introspMsg}`,
      module:      'apiDiscovery',
      affected:    gql.url,
      remediation: gql.introspection
        ? 'Disable GraphQL introspection in production to prevent schema enumeration. Implement depth limiting and query complexity analysis.'
        : 'Review GraphQL endpoint access controls and implement rate limiting.',
      types:       gql.types,
    });
  }

  for (const rest of restFound) {
    if (rest.requiresAuth) continue; // Auth-required endpoints are lower risk info
    results.findings.push({
      id:          `API-REST-${rest.path.replace(/\//g, '-')}`,
      severity:    'info',
      title:       `Public REST API Endpoint: ${rest.path}`,
      description: `REST API endpoint accessible at ${rest.url} (HTTP ${rest.httpStatus}).`,
      module:      'apiDiscovery',
      affected:    rest.url,
      remediation: 'Ensure this endpoint implements proper authentication, rate limiting, and input validation.',
    });
  }

  for (const wsdl of wsdlFound) {
    results.findings.push({
      id:          `API-WSDL-${wsdl.path.replace(/\//g, '-')}`,
      severity:    'low',
      title:       `WSDL/SOAP Endpoint Exposed: ${wsdl.path}`,
      description: `SOAP web service found at ${wsdl.url}. Services: ${wsdl.services.join(', ')}`,
      module:      'apiDiscovery',
      affected:    wsdl.url,
      remediation: 'Review SOAP endpoint access controls. Older SOAP services may have XML injection vulnerabilities.',
    });
  }

  const total = results.summary.total;
  const jsCount = jsEndpoints.length;
  const msg = `API Discovery complete — ${total} public API endpoint(s) found, ${jsCount} endpoint(s) extracted from JS files`;
  onProgress(msg);

  return results;
}

module.exports = { runAPIDiscovery };
