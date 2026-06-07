'use strict';
const express = require('express');
const alertEngine = require('../utils/alertEngine');

module.exports = () => {
  const router = express.Router();

  // GET /api/alerts/history — all fired alerts
  router.get('/history', (req, res) => {
    res.json(alertEngine.getHistory());
  });

  // GET /api/alerts/unread — count of unread alerts
  router.get('/unread', (req, res) => {
    res.json({ count: alertEngine.getUnreadCount() });
  });

  // PATCH /api/alerts/:id/read — mark alert as read
  router.patch('/:id/read', (req, res) => {
    const ok = alertEngine.markRead(req.params.id);
    if (!ok) return res.status(404).json({ error: 'Alert not found' });
    res.json({ ok: true });
  });

  // POST /api/alerts/read-all — mark all as read
  router.post('/read-all', (req, res) => {
    alertEngine.markAllRead();
    res.json({ ok: true });
  });

  // GET /api/alerts/rules — list all rules
  router.get('/rules', (req, res) => {
    res.json(alertEngine.getRules());
  });

  // POST /api/alerts/rules — create a rule
  router.post('/rules', (req, res) => {
    const rule = alertEngine.addRule(req.body);
    res.status(201).json(rule);
  });

  // PUT /api/alerts/rules/:id — update a rule
  router.put('/rules/:id', (req, res) => {
    const rule = alertEngine.updateRule(req.params.id, req.body);
    if (!rule) return res.status(404).json({ error: 'Rule not found' });
    res.json(rule);
  });

  // DELETE /api/alerts/rules/:id — delete a rule
  router.delete('/rules/:id', (req, res) => {
    const ok = alertEngine.removeRule(req.params.id);
    if (!ok) return res.status(404).json({ error: 'Rule not found' });
    res.json({ ok: true });
  });

  // GET /api/alerts/config — get webhook/email config
  router.get('/config', (req, res) => {
    const cfg = alertEngine.getConfig();
    // Mask passwords
    const safe = { ...cfg, email: { ...cfg.email, pass: cfg.email?.pass ? '••••••••' : '' } };
    res.json(safe);
  });

  // PUT /api/alerts/config — update webhook/email config
  router.put('/config', (req, res) => {
    alertEngine.updateConfig(req.body);
    res.json({ ok: true });
  });

  // POST /api/alerts/test — fire a test alert
  router.post('/test', (req, res) => {
    const alert = alertEngine.fireTestAlert();
    res.json({ ok: true, alert });
  });

  return router;
};
