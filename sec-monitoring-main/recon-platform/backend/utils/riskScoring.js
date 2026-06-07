/**
 * Risk Scoring Engine — Enhanced
 * Produces a 0-100 risk score, letter grade, OWASP tagging, and wapiti boost.
 */

const SEVERITY_WEIGHTS = { critical: 25, high: 15, medium: 7, low: 2, info: 0 };
const MAX_SCORE = 100;

// OWASP Top 10 2021 mapping
const OWASP_MAP = {
  sqli:    'A03:2021 Injection',
  xss:     'A03:2021 Injection',
  cmdi:    'A03:2021 Injection',
  lfi:     'A01:2021 Broken Access Control',
  crlf:    'A03:2021 Injection',
  ssti:    'A03:2021 Injection',
  cors:    'A01:2021 Broken Access Control',
  csrf:    'A01:2021 Broken Access Control',
  hdr:     'A05:2021 Security Misconfiguration',
  csp:     'A05:2021 Security Misconfiguration',
  https:   'A02:2021 Cryptographic Failures',
  ssl:     'A02:2021 Cryptographic Failures',
  cookie:  'A02:2021 Cryptographic Failures',
  jwt:     'A02:2021 Cryptographic Failures',
  file:    'A05:2021 Security Misconfiguration',
  cve:     'A06:2021 Vulnerable and Outdated Components',
  cms:     'A05:2021 Security Misconfiguration',
  info:    'A09:2021 Security Logging and Monitoring Failures',
};

function tagFindings(findings) {
  return findings.map(f => {
    if (f.owasp) return f; // already tagged
    const id = (f.id || '').toLowerCase();
    let owasp = 'A05:2021 Security Misconfiguration';
    for (const [key, tag] of Object.entries(OWASP_MAP)) {
      if (id.includes(key)) { owasp = tag; break; }
    }
    return { ...f, owasp };
  });
}

function calculateRiskScore(scan) {
  const rawFindings = scan.findings || [];
  const findings = tagFindings(rawFindings);
  // Mutate findings in-place to add owasp tags
  findings.forEach((f, i) => { if (scan.findings[i]) scan.findings[i].owasp = f.owasp; });

  if (findings.length === 0) {
    return { score: 5, grade: 'A+', label: 'Excellent', breakdown: {}, color: '#22c55e' };
  }

  const breakdown = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high:     findings.filter(f => f.severity === 'high').length,
    medium:   findings.filter(f => f.severity === 'medium').length,
    low:      findings.filter(f => f.severity === 'low').length,
    info:     findings.filter(f => f.severity === 'info').length,
  };

  let rawScore = 0;
  rawScore += Math.min(breakdown.critical * SEVERITY_WEIGHTS.critical, 60);
  rawScore += Math.min(breakdown.high     * SEVERITY_WEIGHTS.high,     40);
  rawScore += Math.min(breakdown.medium   * SEVERITY_WEIGHTS.medium,   25);
  rawScore += Math.min(breakdown.low      * SEVERITY_WEIGHTS.low,      10);

  // Wapiti active findings boost score significantly
  const wapiti = scan.modules?.wapitiscan?.data?.summary || {};
  if (wapiti.sqli  > 0) rawScore += 20; // SQL injection is very serious
  if (wapiti.cmdi  > 0) rawScore += 25; // RCE potential
  if (wapiti.lfi   > 0) rawScore += 20; // file disclosure
  if (wapiti.xss   > 0) rawScore += 10;
  if (wapiti.ssti  > 0) rawScore += 25;

  // Bonus for dangerous combinations
  if (breakdown.critical > 0 && breakdown.high > 2) rawScore += 10;
  if (scan.modules?.portScan?.data?.exposedDangerousPorts?.length > 3) rawScore += 10;
  if (!scan.modules?.dnsAssessment?.data?.spf?.present)   rawScore += 5;
  if (!scan.modules?.dnsAssessment?.data?.dmarc?.present) rawScore += 5;

  // Log4Shell / Spring4Shell specific (very critical)
  const hasLog4j = findings.some(f => f.id?.includes('CVE-2021-44228'));
  const hasSpring4 = findings.some(f => f.id?.includes('CVE-2022-22963'));
  if (hasLog4j || hasSpring4) rawScore = Math.max(rawScore, 90);

  const score = Math.min(Math.round(rawScore), MAX_SCORE);

  return {
    score,
    grade: scoreToGrade(score),
    label: scoreToLabel(score),
    breakdown,
    riskLevel: scoreToLevel(score),
    color: scoreToColor(score),
  };
}

function scoreToGrade(s) {
  if (s <= 10) return 'A+';
  if (s <= 20) return 'A';
  if (s <= 30) return 'B';
  if (s <= 45) return 'C';
  if (s <= 60) return 'D';
  if (s <= 75) return 'E';
  return 'F';
}
function scoreToLabel(s) {
  if (s <= 10) return 'Excellent';
  if (s <= 20) return 'Good';
  if (s <= 35) return 'Moderate';
  if (s <= 55) return 'High Risk';
  if (s <= 75) return 'Critical';
  return 'Severe';
}
function scoreToLevel(s) {
  if (s <= 20) return 'low';
  if (s <= 45) return 'medium';
  if (s <= 70) return 'high';
  return 'critical';
}
function scoreToColor(s) {
  if (s <= 20) return '#22c55e';
  if (s <= 45) return '#f59e0b';
  if (s <= 70) return '#ef4444';
  return '#7f1d1d';
}

module.exports = { calculateRiskScore };
