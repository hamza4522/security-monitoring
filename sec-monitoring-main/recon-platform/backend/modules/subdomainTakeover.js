'use strict';
/**
 * subdomainTakeover.js — Dangling DNS & Subdomain Takeover Detector
 *
 * For each discovered subdomain:
 *   1. Resolves full CNAME chain
 *   2. Matches against 30+ known cloud-service CNAME patterns
 *   3. Fetches the resolved host and checks for service-specific
 *      "unclaimed resource" fingerprints from the can-i-take-over-xyz database
 *
 * References:
 *   - https://github.com/EdOverflow/can-i-take-over-xyz
 *   - https://github.com/projectdiscovery/nuclei-templates (takeover templates)
 */

const dns = require('dns').promises;

const UA = 'Mozilla/5.0 (compatible; SecurityScanner/2.0)';
const PROBE_TIMEOUT = 8000;
const MAX_TARGETS   = 40; // limit to avoid very long scans

// ── Takeover Fingerprints DB ──────────────────────────────────────────────────
// Each entry: {
//   service     — display name
//   cnames      — CNAME patterns that indicate this service
//   fingerprints— body strings that indicate "unclaimed" (vulnerable)
//   statusCodes — HTTP status codes that indicate unclaimed (optional)
//   severity    — severity if takeover is possible
//   description — description of the risk
//   fix         — remediation
//   claimed     — fingerprints in body that prove it IS claimed (exclude false positives)
// }

const TAKEOVER_DB = [
  {
    service: 'GitHub Pages',
    cnames: [/\.github\.io$/i, /\.github\.com$/i],
    fingerprints: ["There isn't a GitHub Pages site here.", "For root URLs (aka your home page), GitHub Pages checks"],
    statusCodes: [404],
    severity: 'high',
    description: 'This subdomain has a CNAME pointing to GitHub Pages, but the GitHub Pages site does not exist. An attacker can create a GitHub Pages site at that name and serve arbitrary content.',
    fix: 'Delete the CNAME record for this subdomain or create a GitHub Pages site at the target username/repo.',
  },
  {
    service: 'Heroku',
    cnames: [/\.herokuapp\.com$/i, /\.herokudns\.com$/i],
    fingerprints: ['No such app', 'There\'s nothing here, yet.', 'Heroku | No such app'],
    statusCodes: [404, 200],
    severity: 'critical',
    description: 'CNAME points to Heroku but the app does not exist. An attacker can create a free Heroku app with the same name to hijack this subdomain.',
    fix: 'Remove the CNAME record or deploy a Heroku app at the target name immediately.',
  },
  {
    service: 'AWS S3 Bucket',
    cnames: [/\.s3\.amazonaws\.com$/i, /\.s3-website[\w-]+\.amazonaws\.com$/i, /\.s3\.\w+-\w+-\d\.amazonaws\.com$/i],
    fingerprints: ['NoSuchBucket', 'The specified bucket does not exist', 'BucketNotFound'],
    statusCodes: [404],
    severity: 'critical',
    description: 'CNAME points to an AWS S3 bucket that does not exist. An attacker can create an S3 bucket with the same name in any AWS account and serve malicious content.',
    fix: 'Create an S3 bucket with the exact name referenced in the CNAME, or remove the CNAME record.',
  },
  {
    service: 'AWS Elastic Beanstalk',
    cnames: [/\.elasticbeanstalk\.com$/i],
    fingerprints: ['Error 404', '404 Not Found', 'The page you are looking for is not found'],
    statusCodes: [404],
    severity: 'critical',
    description: 'CNAME points to AWS Elastic Beanstalk environment that no longer exists.',
    fix: 'Remove the CNAME or recreate the Elastic Beanstalk environment.',
  },
  {
    service: 'Fastly CDN',
    cnames: [/\.fastly\.net$/i, /\.fastlylb\.net$/i, /global\.ssl\.fastly\.net$/i],
    fingerprints: ['Fastly error: unknown domain', 'Please check that this domain has been added to a service'],
    statusCodes: [404, 500],
    severity: 'high',
    description: 'CNAME points to Fastly CDN but the domain is not configured in any Fastly service.',
    fix: 'Remove the CNAME record or configure the domain in your Fastly service.',
  },
  {
    service: 'Microsoft Azure Web Apps',
    cnames: [/\.azurewebsites\.net$/i, /\.azurestaticapps\.net$/i, /\.azure-api\.net$/i, /\.cloudapp\.net$/i],
    fingerprints: ['404 Web Site not found', 'Azure Web Sites', 'This web site does not have a resource'],
    statusCodes: [404],
    severity: 'critical',
    description: 'CNAME points to Azure Web Apps but no application is deployed at the target hostname.',
    fix: 'Deploy an Azure Web App at the target name or remove the CNAME record.',
  },
  {
    service: 'Netlify',
    cnames: [/\.netlify\.app$/i, /\.netlify\.com$/i],
    fingerprints: ['Not Found - Request ID:', 'netlify-cdn', 'If you\'re the site owner'],
    statusCodes: [404],
    severity: 'high',
    description: 'CNAME points to Netlify but the site is not deployed. Attackers can deploy a free Netlify site at this name.',
    fix: 'Deploy a Netlify site at this URL or remove the CNAME record.',
  },
  {
    service: 'Vercel',
    cnames: [/\.vercel\.app$/i, /\.now\.sh$/i, /\.vercel\.com$/i],
    fingerprints: ['The deployment you are looking for is gone', 'This Deployment doesn\'t exist', 'DEPLOYMENT_NOT_FOUND'],
    statusCodes: [404],
    severity: 'high',
    description: 'CNAME points to Vercel but the deployment does not exist.',
    fix: 'Deploy a Vercel project at this domain or remove the CNAME.',
  },
  {
    service: 'Squarespace',
    cnames: [/\.squarespace\.com$/i],
    fingerprints: ['No Such Account', 'This domain or subdomain is not properly set up'],
    statusCodes: [404, 301],
    severity: 'medium',
    description: 'CNAME points to Squarespace but the account does not exist.',
    fix: 'Create a Squarespace account matching the domain or remove the CNAME.',
  },
  {
    service: 'Shopify',
    cnames: [/\.myshopify\.com$/i, /shops\.myshopify\.com$/i],
    fingerprints: ['Sorry, this shop is currently unavailable', 'Only one step left!', 'Sorry, this shop is not available'],
    statusCodes: [404],
    severity: 'medium',
    description: 'CNAME points to Shopify but the store does not exist.',
    fix: 'Create the Shopify store or remove the CNAME.',
  },
  {
    service: 'Ghost (Blog)',
    cnames: [/\.ghost\.io$/i],
    fingerprints: ['The thing you were looking for is no longer here', 'Failed to load'],
    statusCodes: [404],
    severity: 'medium',
    description: 'CNAME points to Ghost.io blogging platform but the blog does not exist.',
    fix: 'Create the Ghost blog or remove the CNAME.',
  },
  {
    service: 'WordPress.com',
    cnames: [/\.wordpress\.com$/i],
    fingerprints: ['Do you want to register', 'doesn\'t exist'],
    statusCodes: [404],
    severity: 'medium',
    description: 'CNAME points to WordPress.com but the blog does not exist.',
    fix: 'Create the WordPress.com blog or remove the CNAME.',
  },
  {
    service: 'Zendesk Help Center',
    cnames: [/\.zendesk\.com$/i, /\.zdassets\.com$/i],
    fingerprints: ['Help Center Closed', 'This help center no longer exists'],
    statusCodes: [404],
    severity: 'high',
    description: 'CNAME points to Zendesk but the help center has been deleted.',
    fix: 'Create the Zendesk help center or remove the CNAME.',
  },
  {
    service: 'HubSpot',
    cnames: [/\.hs-sites\.com$/i, /\.hubspot\.net$/i, /\.hubspotpagebuilder\.com$/i],
    fingerprints: ['Domain is not connected', 'does not exist in our system', '404 Not Found'],
    statusCodes: [404],
    severity: 'high',
    description: 'CNAME points to HubSpot but the landing page or CMS does not exist.',
    fix: 'Create the HubSpot page or remove the CNAME.',
  },
  {
    service: 'Surge.sh',
    cnames: [/\.surge\.sh$/i],
    fingerprints: ['project not found', '404 Not Found'],
    statusCodes: [404],
    severity: 'high',
    description: 'CNAME points to Surge.sh static hosting but the project was removed.',
    fix: 'Deploy to Surge.sh at this domain or remove the CNAME.',
  },
  {
    service: 'Fly.io',
    cnames: [/\.fly\.dev$/i, /\.fly\.io$/i],
    fingerprints: ['404: This page could not be found', 'fly.io'],
    statusCodes: [404],
    severity: 'high',
    description: 'CNAME points to Fly.io but the app does not exist.',
    fix: 'Deploy to Fly.io or remove the CNAME.',
  },
  {
    service: 'Render',
    cnames: [/\.onrender\.com$/i],
    fingerprints: ['Service Unavailable', 'Render is the cloud for building and running apps'],
    statusCodes: [404, 503],
    severity: 'high',
    description: 'CNAME points to Render.com but the service does not exist.',
    fix: 'Deploy to Render or remove the CNAME.',
  },
  {
    service: 'DigitalOcean App Platform',
    cnames: [/\.ondigitalocean\.app$/i],
    fingerprints: ['404 Not Found', 'Domain not found'],
    statusCodes: [404],
    severity: 'high',
    description: 'CNAME points to DigitalOcean App Platform but the app does not exist.',
    fix: 'Create the DigitalOcean app or remove the CNAME.',
  },
  {
    service: 'Intercom',
    cnames: [/\.intercom\.help$/i, /\.intercom\.io$/i],
    fingerprints: ['Uh oh. That page doesn\'t exist.', 'Page not found - Intercom'],
    statusCodes: [404],
    severity: 'medium',
    description: 'CNAME points to Intercom help center that no longer exists.',
    fix: 'Create the Intercom help center or remove the CNAME.',
  },
  {
    service: 'Bitbucket Pages',
    cnames: [/\.bitbucket\.io$/i],
    fingerprints: ['Repository not found', '404: Not Found'],
    statusCodes: [404],
    severity: 'high',
    description: 'CNAME points to Bitbucket Pages but the repository does not exist.',
    fix: 'Create the Bitbucket repository or remove the CNAME.',
  },
  {
    service: 'Webflow',
    cnames: [/\.webflow\.io$/i],
    fingerprints: ["The page you are looking for doesn't exist or has been moved"],
    statusCodes: [404],
    severity: 'medium',
    description: 'CNAME points to Webflow but the site does not exist.',
    fix: 'Create the Webflow site or remove the CNAME.',
  },
  {
    service: 'Pantheon',
    cnames: [/\.pantheonsite\.io$/i, /\.getpantheon\.com$/i],
    fingerprints: ['404 error unknown site!', '404 Not Found'],
    statusCodes: [404],
    severity: 'high',
    description: 'CNAME points to Pantheon but the site does not exist.',
    fix: 'Create the Pantheon site or remove the CNAME.',
  },
  {
    service: 'ReadMe.io Documentation',
    cnames: [/\.readme\.io$/i, /\.readme\.com$/i],
    fingerprints: ['Project doesnt exist... yet!', 'This page is not found'],
    statusCodes: [404],
    severity: 'medium',
    description: 'CNAME points to ReadMe documentation platform but the project is unclaimed.',
    fix: 'Create the ReadMe project or remove the CNAME.',
  },
  {
    service: 'Launchrock',
    cnames: [/\.launchrock\.com$/i],
    fingerprints: ["It's not here, sorry!"],
    statusCodes: [404],
    severity: 'medium',
    description: 'CNAME points to Launchrock but the site is not created.',
    fix: 'Remove the CNAME record.',
  },
];

// ── DNS CNAME Resolver ─────────────────────────────────────────────────────────

async function resolveCNAMEChain(domain, maxDepth = 5) {
  const chain = [domain];
  let current = domain;
  for (let i = 0; i < maxDepth; i++) {
    try {
      const results = await dns.resolveCname(current);
      if (!results || results.length === 0) break;
      current = results[0];
      chain.push(current);
    } catch (_) {
      break; // ENODATA = no more CNAMEs in chain
    }
  }
  return chain;
}

// ── HTTP Fingerprint Probe ────────────────────────────────────────────────────

async function probeTakeover(subdomain, cnameTarget) {
  try {
    const r = await fetch(`http://${subdomain}`, {
      redirect: 'follow',
      signal: AbortSignal.timeout(PROBE_TIMEOUT),
      headers: { 'User-Agent': UA },
    });
    const body = await r.text().catch(() => '');
    return { status: r.status, body, ok: true };
  } catch (_) {
    // Try HTTPS
    try {
      const r = await fetch(`https://${subdomain}`, {
        redirect: 'follow',
        signal: AbortSignal.timeout(PROBE_TIMEOUT),
        headers: { 'User-Agent': UA },
      });
      const body = await r.text().catch(() => '');
      return { status: r.status, body, ok: true };
    } catch (_2) {
      return { status: 0, body: '', ok: false };
    }
  }
}

function matchTakeoverDB(cnameChain, probeResult) {
  for (const entry of TAKEOVER_DB) {
    // Check if any CNAME in chain matches this service
    const cnameMatch = cnameChain.some(c => entry.cnames.some(pattern => pattern.test(c)));
    if (!cnameMatch) continue;

    // Require a body fingerprint match — status code alone is NOT sufficient
    // (many services return 404 for normal requests without being vulnerable)
    const bodyMatch = entry.fingerprints.some(fp =>
      probeResult.body.toLowerCase().includes(fp.toLowerCase())
    );

    if (bodyMatch) return entry;
  }
  return null;
}

// ── Main Export ───────────────────────────────────────────────────────────────

async function runSubdomainTakeover(domain, onProgress, subdomains = []) {
  const results = {
    domain,
    checked:     [],
    vulnerable:  [],
    findings:    [],
    summary: { checked: 0, vulnerable: 0, servicesScanned: TAKEOVER_DB.length },
  };

  // Combine main domain with passed subdomains, deduplicate, limit
  const targets = [...new Set([domain, ...subdomains])].slice(0, MAX_TARGETS);
  results.summary.checked = targets.length;

  onProgress(`Checking ${targets.length} subdomains for takeover vulnerabilities (${TAKEOVER_DB.length} service fingerprints)...`);

  const checks = targets.map(async (subdomain) => {
    try {
      // Resolve CNAME chain
      const cnameChain = await resolveCNAMEChain(subdomain);
      if (cnameChain.length < 2) return; // No CNAME — not vulnerable to CNAME takeover

      const cnameTarget = cnameChain[cnameChain.length - 1];

      // Check if CNAME points to a known cloud service
      const serviceMatch = TAKEOVER_DB.some(e => e.cnames.some(p => p.test(cnameTarget)));
      if (!serviceMatch) return;

      // Try to resolve the CNAME target — if NXDOMAIN, likely dangling
      let targetNXDOMAIN = false;
      try {
        await dns.resolve4(cnameTarget);
      } catch (e) {
        if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') {
          targetNXDOMAIN = true;
        }
      }

      // Probe the subdomain for takeover fingerprints
      const probe = await probeTakeover(subdomain, cnameTarget);

      results.checked.push({
        subdomain,
        cnameChain,
        cnameTarget,
        targetNXDOMAIN,
        status: probe.status,
      });

      // Match fingerprints or NXDOMAIN
      const matched = matchTakeoverDB(cnameChain, probe);

      if (matched || targetNXDOMAIN) {
        const service = matched?.service || 'Unknown Service';
        results.vulnerable.push({ subdomain, cnameChain, service });
        results.summary.vulnerable++;

        results.findings.push({
          id:          `TAKEOVER-${subdomain.replace(/\./g, '-').toUpperCase()}`,
          severity:    matched?.severity || 'high',
          title:       `Subdomain Takeover Possible: ${subdomain} → ${service}`,
          description: matched
            ? `${matched.description}\nCNAME chain: ${cnameChain.join(' → ')}`
            : `Subdomain ${subdomain} has a CNAME pointing to ${cnameTarget} which returned NXDOMAIN (no IP). This dangling DNS entry is potentially vulnerable to takeover.`,
          module:      'subdomainTakeover',
          affected:    subdomain,
          remediation: matched?.fix || 'Remove the CNAME record for this subdomain immediately.',
          details: { cnameChain, cnameTarget, targetNXDOMAIN, httpStatus: probe.status },
        });
      }
    } catch (_) {}
  });

  await Promise.allSettled(checks);

  onProgress(`Takeover scan complete — ${results.summary.vulnerable} vulnerable, ${results.summary.checked} checked`);
  return results;
}

module.exports = { runSubdomainTakeover };
