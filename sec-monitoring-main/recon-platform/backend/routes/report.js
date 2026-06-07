const express = require('express');

module.exports = (scans) => {
  const router = express.Router();

  // Get JSON report for a scan
  router.get('/:scanId/json', (req, res) => {
    const scan = scans.get(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (scan.status !== 'complete') return res.status(400).json({ error: 'Scan not complete yet' });
    res.json(scan);
  });

  // Get executive summary
  router.get('/:scanId/executive', (req, res) => {
    const scan = scans.get(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    const execReport = {
      domain: scan.domain,
      scanDate: scan.completedAt,
      riskScore: scan.riskScore,
      summary: scan.summary,
      topFindings: scan.findings
        .sort((a, b) => severityOrder(b.severity) - severityOrder(a.severity))
        .slice(0, 10)
        .map(f => ({
          title: f.title,
          severity: f.severity,
          remediation: f.remediation,
        })),
      recommendations: generateExecutiveRecommendations(scan),
    };

    res.json(execReport);
  });

  // Download PDF report
  router.get('/:scanId/pdf', (req, res) => {
    const scan = scans.get(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    
    let PDFDocument;
    try {
      PDFDocument = require('pdfkit');
    } catch (err) {
      return res.status(500).json({ error: 'PDF module not installed on backend.' });
    }
    
    const doc = new PDFDocument({ margin: 50 });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="reconScan-${scan.domain}-${Date.now()}.pdf"`);
    doc.pipe(res);

    // Title
    doc.fontSize(24).fillColor('#1e293b').text('ReconScan Security Report', { align: 'center' });
    doc.moveDown(1.5);
    
    // Meta
    doc.fontSize(12).fillColor('#334155');
    doc.text(`Target Domain: ${scan.domain}`);
    doc.text(`Scan Date: ${new Date(scan.completedAt || scan.startedAt).toUTCString()}`);
    doc.text(`Risk Score: ${scan.riskScore?.score ?? '—'} / 100 (Grade: ${scan.riskScore?.grade ?? '?'})`);
    doc.text(`Total Findings: ${scan.findings?.length ?? 0}`);
    doc.moveDown(2);

    // Exec Summary
    doc.fontSize(16).fillColor('#1e293b').text('Executive Summary');
    doc.moveDown(0.5);
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    (scan.findings || []).forEach(f => counts[f.severity] = (counts[f.severity] || 0) + 1);
    
    doc.fontSize(12).fillColor('#334155');
    doc.text(`Critical: ${counts.critical}`);
    doc.text(`High: ${counts.high}`);
    doc.text(`Medium: ${counts.medium}`);
    doc.text(`Low: ${counts.low}`);
    doc.text(`Info: ${counts.info}`);
    doc.moveDown(2);

    // Findings
    doc.fontSize(16).fillColor('#1e293b').text('Findings Detail');
    doc.moveDown(1);

    const sorted = [...(scan.findings || [])].sort((a,b) =>
      ({ critical:0, high:1, medium:2, low:3, info:4 }[a.severity]??5) - ({ critical:0, high:1, medium:2, low:3, info:4 }[b.severity]??5));

    sorted.forEach((f, i) => {
      const color = f.severity === 'critical' ? '#e11d48' : f.severity === 'high' ? '#d97706' : '#3b82f6';
      doc.fontSize(14).fillColor(color).text(`${i+1}. [${f.severity.toUpperCase()}] ${f.title}`);
      doc.fontSize(10).fillColor('#64748b').text(`Module: ${f.module}`);
      doc.moveDown(0.5);
      doc.fontSize(11).fillColor('#334155').text(`Description: ${f.description}`, { align: 'justify' });
      if (f.affected) {
        doc.moveDown(0.3);
        doc.text(`Affected: ${f.affected}`);
      }
      if (f.remediation) {
        doc.moveDown(0.3);
        doc.text(`Remediation: ${f.remediation}`, { align: 'justify' });
      }
      doc.moveDown(1.5);
    });

    doc.end();
  });

  // Download Markdown report
  router.get('/:scanId/markdown', (req, res) => {
    const scan = scans.get(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    const md = buildMarkdownReport(scan);
    res.setHeader('Content-Type', 'text/markdown');
    res.setHeader('Content-Disposition', `attachment; filename="reconScan-${scan.domain}-${Date.now()}.md"`);
    res.send(md);
  });

  // Download full JSON report
  router.get('/:scanId/download', (req, res) => {
    const scan = scans.get(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="reconScan-${scan.domain}-${Date.now()}.json"`);
    res.json(scan);
  });

  return router;
};

function severityOrder(s) {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] || 0;
}

function generateExecutiveRecommendations(scan) {
  const recs = [];
  const { riskScore, findings } = scan;
  if (findings.some(f => f.severity === 'critical')) {
    recs.push({ priority: 'Immediate (24-48h)', action: 'Address all critical severity findings immediately',
      items: findings.filter(f => f.severity === 'critical').map(f => f.title) });
  }
  if (findings.some(f => f.severity === 'high')) {
    recs.push({ priority: 'Short-term (1-2 weeks)', action: 'Remediate high severity vulnerabilities',
      items: findings.filter(f => f.severity === 'high').map(f => f.title).slice(0, 5) });
  }
  if (riskScore?.score > 50) {
    recs.push({ priority: 'Strategic', action: 'Engage security team for comprehensive assessment',
      items: ['Penetration testing', 'Security architecture review', 'Incident response planning'] });
  }
  return recs;
}

function buildMarkdownReport(scan) {
  const sevEmoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', info: '🔵' };
  const sorted = [...(scan.findings || [])].sort((a,b) =>
    ({ critical:0, high:1, medium:2, low:3, info:4 }[a.severity]??5) - ({ critical:0, high:1, medium:2, low:3, info:4 }[b.severity]??5));

  const lines = [
    `# ReconScan Security Report`,
    ``,
    `**Target Domain:** \`${scan.domain}\``,
    `**Scan Date:** ${new Date(scan.completedAt || scan.startedAt).toUTCString()}`,
    `**Risk Score:** ${scan.riskScore?.score ?? '—'} / 100 — Grade **${scan.riskScore?.grade ?? '?'}** (${scan.riskScore?.label ?? ''})`,
    `**Total Findings:** ${scan.findings?.length ?? 0}`,
    ``,
    `---`,
    ``,
    `## Executive Summary`,
    ``,
    `| Severity | Count |`,
    `|---|---|`,
    `| 🔴 Critical | ${scan.findings?.filter(f=>f.severity==='critical').length ?? 0} |`,
    `| 🟠 High | ${scan.findings?.filter(f=>f.severity==='high').length ?? 0} |`,
    `| 🟡 Medium | ${scan.findings?.filter(f=>f.severity==='medium').length ?? 0} |`,
    `| 🟢 Low | ${scan.findings?.filter(f=>f.severity==='low').length ?? 0} |`,
    `| 🔵 Info | ${scan.findings?.filter(f=>f.severity==='info').length ?? 0} |`,
    ``,
    `---`,
    ``,
    `## Findings`,
    ``,
    ...sorted.map((f, i) => [
      `### ${i+1}. ${sevEmoji[f.severity]||'⚪'} [${f.severity?.toUpperCase()}] ${f.title}`,
      ``,
      `**Module:** \`${f.module}\`${f.owasp ? `  **OWASP:** ${f.owasp}` : ''}`,
      ``,
      `**Description:** ${f.description}`,
      ``,
      f.affected ? `**Affected:** \`${f.affected}\`` : '',
      ``,
      f.remediation ? `**Remediation:** ${f.remediation}` : '',
      ``,
      `---`,
      ``,
    ].filter(l => l !== undefined).join('\n')),
    ``,
    `## Scan Modules`,
    ``,
    ...Object.entries(scan.modules || {}).map(([key, mod]) =>
      `- **${key}**: ${mod.status}`),
    ``,
    `---`,
    ``,
    `*Generated by ReconScan — For authorized use only*`,
  ];
  return lines.join('\n');
}
