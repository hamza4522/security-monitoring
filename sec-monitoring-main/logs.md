# 📋 DevOps Logging Reference Guide

> A comprehensive reference for DevOps, SRE, and Platform engineers covering everything about logs — types, formats, levels, collection, aggregation, parsing, analysis, retention, and best practices across all environments.

---

## Table of Contents

1. [What Are Logs?](#1-what-are-logs)
2. [Log Levels / Severity](#2-log-levels--severity)
3. [Log Types & Categories](#3-log-types--categories)
4. [Log Formats](#4-log-formats)
5. [Structured vs Unstructured Logging](#5-structured-vs-unstructured-logging)
6. [Log Collection & Shipping](#6-log-collection--shipping)
7. [Log Aggregation & Storage](#7-log-aggregation--storage)
8. [Log Parsing & Processing](#8-log-parsing--processing)
9. [Log Analysis & Search](#9-log-analysis--search)
10. [Log Monitoring & Alerting](#10-log-monitoring--alerting)
11. [Application Logging Best Practices](#11-application-logging-best-practices)
12. [Docker & Container Logging](#12-docker--container-logging)
13. [Kubernetes Logging Architecture](#13-kubernetes-logging-architecture)
14. [Cloud Provider Logging (AWS / GCP / Azure)](#14-cloud-provider-logging-aws--gcp--azure)
15. [Security & Audit Logging](#15-security--audit-logging)
16. [Log Retention & Compliance](#16-log-retention--compliance)
17. [Log Cost Optimization](#17-log-cost-optimization)
18. [Distributed Tracing vs Logging](#18-distributed-tracing-vs-logging)
19. [ELK / EFK Stack Deep Dive](#19-elk--efk-stack-deep-dive)
20. [Grafana Loki Deep Dive](#20-grafana-loki-deep-dive)
21. [Quick Reference & Cheat Sheets](#21-quick-reference--cheat-sheets)

---

## 1. What Are Logs?

**Definition**: Logs are timestamped, immutable records of events that occurred within a system, application, or infrastructure component. They are one of the three pillars of observability alongside **metrics** and **traces**.

### The Three Pillars of Observability

```
┌─────────────────────────────────────────────────────┐
│                  OBSERVABILITY                       │
├─────────────┬──────────────────┬────────────────────┤
│   METRICS   │      LOGS        │      TRACES        │
│             │                  │                    │
│ "What is    │ "What happened   │ "Why did this      │
│  happening  │  and when?"      │  request take      │
│  right now?"│                  │  so long?"         │
│             │                  │                    │
│ Numbers     │ Text events      │ Request journey    │
│ Time-series │ Timestamped      │ across services    │
│ Aggregated  │ Detailed context │ Span-based         │
└─────────────┴──────────────────┴────────────────────┘
```

### Why Logs Matter
- **Debugging**: Pinpoint exact line of code and state when failure occurred
- **Auditing**: Prove who did what and when (compliance)
- **Security**: Detect attacks, intrusion, and anomalous behavior
- **Performance Analysis**: Identify slow queries, bottlenecks, timeouts
- **Root Cause Analysis**: Trace the chain of events leading to an incident
- **Business Intelligence**: User behavior, feature usage, conversion tracking

### Log Lifecycle

```
Application/System
       │
       ▼ Generate
  Log Event Created
       │
       ▼ Collect
  Log Shipper (Filebeat/Fluentd/Fluent Bit)
       │
       ▼ Transport
  Message Queue (Kafka/Redis) [optional buffer]
       │
       ▼ Process
  Log Processor (Logstash/Vector/Fluentd)
       │
       ▼ Store
  Log Storage (Elasticsearch/Loki/S3/CloudWatch)
       │
       ▼ Index & Search
  Query Engine (Kibana/Grafana/CloudWatch Insights)
       │
       ▼ Alert
  Alerting (PagerDuty/Slack/OpsGenie)
       │
       ▼ Archive
  Cold Storage (S3 Glacier/GCS Archive/Azure Archive)
```

---

## 2. Log Levels / Severity

> Log levels allow you to filter the verbosity of log output. Each level represents a specific severity of event. Using the correct level is critical for operational efficiency.

---

### Standard Log Levels (Syslog RFC 5424)

| Level | Numeric | Keyword | Description | Example |
|---|---|---|---|---|
| 0 | EMERGENCY | `emerg` | System is unusable, immediate action required | Kernel panic, disk full causing system halt |
| 1 | ALERT | `alert` | Immediate action required | Primary database down, all backups failing |
| 2 | CRITICAL | `crit` | Critical condition | Service crashed, OOM kill, data loss risk |
| 3 | ERROR | `error` | Error condition — functionality impaired | Database query failed, API call rejected |
| 4 | WARNING | `warn` | Warning — potential issue | Disk at 85%, retry attempt, deprecated API used |
| 5 | NOTICE | `notice` | Normal but significant event | Config reload, user privilege escalation |
| 6 | INFO | `info` | Informational messages | Server started, request processed, user logged in |
| 7 | DEBUG | `debug` | Debug-level messages | Variable values, function entry/exit |

### Application-Level Log Levels (most common)

| Level | When to Use | Production Default? |
|---|---|---|
| `FATAL` / `CRITICAL` | Process cannot continue, will exit | ✅ Always on |
| `ERROR` | Operation failed, needs attention | ✅ Always on |
| `WARN` | Unusual condition, operation succeeded | ✅ Always on |
| `INFO` | Normal operational messages | ✅ Recommended |
| `DEBUG` | Detailed diagnostic information | ❌ Off in prod (too verbose) |
| `TRACE` | Ultra-verbose, every function call | ❌ Only in dev/testing |

### Log Level Decision Tree

```
Did the operation FAIL completely?
  YES → Is the entire service/process broken?
          YES → FATAL/CRITICAL
          NO  → ERROR
  NO  → Was there something unexpected?
          YES → Is the system still healthy?
                  YES → WARN
                  NO  → ERROR
          NO  → Is this a significant lifecycle event?
                  YES → INFO
                  NO  → DEBUG/TRACE
```

### Log Level Examples

```python
# FATAL - application cannot continue
logger.fatal("Database connection pool exhausted - shutting down")

# ERROR - operation failed, needs investigation
logger.error("Payment processing failed", {
    "order_id": "ORD-12345",
    "error_code": "INSUFFICIENT_FUNDS",
    "amount": 99.99
})

# WARN - potential problem, operation continued
logger.warn("API rate limit at 85%, throttling may occur", {
    "current_rate": 850,
    "limit": 1000,
    "reset_in_seconds": 45
})

# INFO - normal operational events
logger.info("User authentication successful", {
    "user_id": "USR-789",
    "method": "OAuth2",
    "ip": "192.168.1.100"
})

# DEBUG - detailed diagnostic (NOT in production)
logger.debug("Cache lookup result", {
    "key": "session:abc123",
    "hit": false,
    "lookup_time_ms": 2.3
})

# TRACE - ultra-verbose (development only)
logger.trace("Entering function processPayment()", {
    "params": { "amount": 99.99, "currency": "USD" }
})
```

---

## 3. Log Types & Categories

> Different systems generate different types of logs. Understanding each type helps you know what to collect, where to find it, and how to analyze it.

---

### 3.1 Application Logs

**Definition**: Logs emitted directly by your application code.

**Content**: Business logic events, errors, user actions, performance data

**Location**: Varies — stdout/stderr, files, or directly to log aggregator

**Examples**:
```
2026-06-25T01:10:00Z INFO  [OrderService] Order created successfully
  order_id=ORD-12345 user_id=USR-789 amount=99.99 currency=USD duration_ms=145

2026-06-25T01:10:01Z ERROR [PaymentService] Stripe API timeout
  order_id=ORD-12345 timeout_ms=5000 attempt=3 next_retry=disabled
```

**Key fields to always include**:
- Timestamp (ISO 8601 with timezone)
- Log level
- Service/component name
- Correlation/Trace ID
- User/session ID (anonymized if PII)
- Duration for operations
- Error codes and stack traces for errors

---

### 3.2 System Logs (OS Logs)

**Definition**: Logs generated by the operating system kernel and system services.

**Linux Log Locations**:
| Log File | Content |
|---|---|
| `/var/log/syslog` (Debian) / `/var/log/messages` (RHEL) | General system messages |
| `/var/log/auth.log` / `/var/log/secure` | Authentication events (SSH, sudo) |
| `/var/log/kern.log` | Kernel messages |
| `/var/log/dmesg` | Boot-time kernel ring buffer |
| `/var/log/cron` / `/var/log/cron.log` | Cron job execution |
| `/var/log/boot.log` | System boot messages |
| `/var/log/faillog` | Failed login attempts |
| `/var/log/lastlog` | Last login for each user |
| `/var/log/wtmp` | Binary: login/logout history |
| `/var/log/btmp` | Binary: failed login attempts |

**Systemd Journal (modern Linux)**:
```bash
# View all journal logs
journalctl

# Follow live logs (like tail -f)
journalctl -f

# Last 100 lines
journalctl -n 100

# Since last boot
journalctl -b

# Specific service
journalctl -u nginx.service

# Since specific time
journalctl --since "2026-06-25 00:00:00" --until "2026-06-25 01:00:00"

# Priority (error and above)
journalctl -p err

# JSON output
journalctl -o json-pretty
```

---

### 3.3 Web Server / Access Logs

**Definition**: HTTP request logs from web servers (Nginx, Apache, HAProxy).

**Nginx Combined Log Format**:
```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
```

**Example**:
```
192.168.1.100 - john [25/Jun/2026:01:10:00 +0500] "POST /api/orders HTTP/1.1" 201 485 "https://app.example.com/checkout" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
10.0.0.5 - - [25/Jun/2026:01:10:01 +0500] "GET /health HTTP/1.1" 200 18 "-" "kube-probe/1.28"
```

**Fields Explained**:
| Field | Example | Description |
|---|---|---|
| `remote_addr` | 192.168.1.100 | Client IP |
| `remote_user` | john | Auth username (- if none) |
| `time_local` | 25/Jun/2026:01:10:00 | Request timestamp |
| `request` | POST /api/orders HTTP/1.1 | HTTP method, path, version |
| `status` | 201 | HTTP response code |
| `body_bytes_sent` | 485 | Response body size in bytes |
| `http_referer` | https://app.example.com | Referring URL |
| `http_user_agent` | Mozilla/5.0... | Client user agent |

**Extended Nginx Log (add upstream info)**:
```nginx
log_format extended '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" '
                    'rt=$request_time '
                    'uct="$upstream_connect_time" '
                    'uht="$upstream_header_time" '
                    'urt="$upstream_response_time" '
                    'cs=$upstream_cache_status';
```

---

### 3.4 Database Logs

**Definition**: Logs from database engines covering queries, connections, errors, and slow operations.

**PostgreSQL Log Configuration** (`postgresql.conf`):
```ini
log_destination = 'csvlog'
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_rotation_age = 1d
log_rotation_size = 100MB

# Log slow queries
log_min_duration_statement = 1000   # Log queries > 1 second
log_checkpoints = on
log_connections = on
log_disconnections = on
log_lock_waits = on
log_temp_files = 0                  # Log all temp files
log_autovacuum_min_duration = 0

# What to log
log_line_prefix = '%m [%p] %q%u@%d '
log_statement = 'ddl'               # Log all DDL (CREATE, ALTER, DROP)
```

**PostgreSQL Slow Query Example**:
```
2026-06-25 01:10:05.123 UTC [12345] user@orders_db LOG:
  duration: 3421.456 ms  statement:
  SELECT o.*, u.email, u.name
  FROM orders o
  JOIN users u ON o.user_id = u.id
  WHERE o.created_at > '2026-01-01'
  ORDER BY o.created_at DESC;
```

**MySQL Slow Query Log**:
```
# Time: 2026-06-25T01:10:05.123456Z
# User@Host: app_user[app_user] @ 10.0.0.5 [10.0.0.5]
# Query_time: 3.421  Lock_time: 0.002  Rows_sent: 1000  Rows_examined: 5000000
SET timestamp=1719274205;
SELECT * FROM orders WHERE status = 'pending' ORDER BY created_at DESC;
```

**MySQL General Log Location**:
```
/var/log/mysql/mysql.log           # General log (very verbose, off in prod)
/var/log/mysql/mysql-slow.log      # Slow query log
/var/log/mysql/error.log           # Error log
```

---

### 3.5 Security / Authentication Logs

**Definition**: Logs related to authentication, authorization, and security events.

**SSH Authentication Log** (`/var/log/auth.log`):
```
# Successful login
Jun 25 01:10:05 server sshd[1234]: Accepted publickey for devops from 10.0.0.5 port 54321 ssh2

# Failed login (brute force indicator)
Jun 25 01:10:06 server sshd[1235]: Failed password for root from 185.220.101.1 port 12345 ssh2
Jun 25 01:10:06 server sshd[1235]: Failed password for root from 185.220.101.1 port 12345 ssh2
Jun 25 01:10:07 server sshd[1235]: Failed password for root from 185.220.101.1 port 12345 ssh2

# sudo usage
Jun 25 01:10:10 server sudo: devops : TTY=pts/0 ; PWD=/home/devops ; USER=root ; COMMAND=/bin/systemctl restart nginx
```

**Linux PAM Log Events**:
```
# Account locked after failures
Jun 25 01:10:15 server sshd[1240]: pam_tally2(sshd:auth): Excessive login failures

# su/sudo events
Jun 25 01:10:20 server su[1245]: Successful su for root by devops
Jun 25 01:10:25 server sudo[1246]: devops : COMMAND=/usr/bin/apt update
```

---

### 3.6 Network / Firewall Logs

**Definition**: Logs from network devices, firewalls, and packet filters about network traffic.

**iptables Log Entry**:
```
Jun 25 01:10:00 server kernel: [IPTABLES DROP] IN=eth0 OUT= 
  MAC=... SRC=185.220.101.1 DST=10.0.0.5 
  LEN=44 TOS=0x00 TTL=45 ID=12345 
  PROTO=TCP SPT=54321 DPT=22 
  WINDOW=65535 RES=0x00 SYN URGP=0
```

**UFW (Uncomplicated Firewall) Log**:
```
Jun 25 01:10:00 server kernel: [UFW BLOCK] IN=eth0 OUT=
  SRC=185.220.101.1 DST=10.0.0.5
  PROTO=TCP SPT=12345 DPT=3306
  [UFW ALLOW] IN=eth0 SRC=10.0.0.10 DPT=443
```

**VPC Flow Logs (AWS)**:
```
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes windowstart windowend action flowlogstatus
2 123456789 eni-abc12345 10.0.0.5 10.0.1.5 54321 443 6 10 4200 1719274200 1719274260 ACCEPT OK
2 123456789 eni-abc12345 185.220.101.1 10.0.0.5 12345 22 6 3 180 1719274200 1719274260 REJECT OK
```

---

### 3.7 Audit Logs

**Definition**: Immutable records of who did what to which resource and when. Critical for compliance.

**Linux Audit Log** (`/var/log/audit/audit.log`):
```
# File access
type=SYSCALL msg=audit(1719274205.123:456): arch=x86_64 syscall=openat
  success=yes exit=5 a0=AT_FDCWD a1=0x7fff1234 a2=O_RDONLY
  pid=1234 uid=1000 gid=1000 euid=0 egid=0
  comm="cat" exe="/bin/cat" key="sensitive_files"

# Privilege escalation
type=USER_AUTH msg=audit(1719274210.456:789):
  pid=1235 uid=1000 auid=1000 ses=1
  subj=system_u:system_r:sshd_t:s0-s0:c0.c1023
  msg='op=PAM:authentication grantors=pam_unix
  acct="root" exe="/usr/sbin/sshd" hostname=10.0.0.5
  addr=10.0.0.5 terminal=ssh res=success'
```

**Kubernetes Audit Log**:
```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "RequestResponse",
  "auditID": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/production/secrets/db-password",
  "verb": "get",
  "user": {
    "username": "system:serviceaccount:production:api-service",
    "groups": ["system:serviceaccounts", "system:authenticated"]
  },
  "sourceIPs": ["10.0.0.15"],
  "objectRef": {
    "resource": "secrets",
    "namespace": "production",
    "name": "db-password",
    "apiVersion": "v1"
  },
  "responseStatus": { "code": 200 },
  "requestReceivedTimestamp": "2026-06-25T01:10:05.123456Z",
  "stageTimestamp": "2026-06-25T01:10:05.145678Z"
}
```

---

### 3.8 Infrastructure & Cloud Logs

| Log Type | Source | Description |
|---|---|---|
| **CloudTrail** (AWS) | API calls | Every AWS API call: who, what, when, where |
| **Cloud Audit Logs** (GCP) | API calls | GCP equivalent of CloudTrail |
| **Activity Log** (Azure) | Subscription events | Azure control plane operations |
| **VPC Flow Logs** | Network traffic | IP-level traffic data |
| **Load Balancer Logs** | ALB/NLB/CLB | HTTP request logs from AWS LB |
| **WAF Logs** | Web Application Firewall | Blocked/allowed requests |
| **DNS Query Logs** | Route53/Cloud DNS | DNS lookups and resolutions |
| **S3 Access Logs** | Object storage | API calls to S3 buckets |
| **Config Change Logs** | AWS Config / GCP Config | Resource configuration changes |

---

### 3.9 CI/CD Pipeline Logs

**Definition**: Logs generated by CI/CD pipeline runs — build, test, deploy stages.

**GitHub Actions Log Structure**:
```
2026-06-25T01:10:00.000Z Run: actions/checkout@v4
2026-06-25T01:10:02.345Z Cloning repository...
2026-06-25T01:10:05.678Z Checking out commit a1b2c3d4

2026-06-25T01:10:10.000Z Run: npm install
2026-06-25T01:10:10.123Z added 1547 packages in 45s
2026-06-25T01:10:55.456Z Packages audited: 1547
2026-06-25T01:10:55.789Z found 0 vulnerabilities

2026-06-25T01:11:00.000Z Run: npm test
2026-06-25T01:11:30.123Z Tests: 245 passed, 0 failed
2026-06-25T01:11:30.456Z Coverage: 84.3%

2026-06-25T01:12:00.000Z Run: docker build -t api:a1b2c3d4 .
2026-06-25T01:12:45.789Z Successfully built 1a2b3c4d5e6f
2026-06-25T01:12:46.000Z Successfully tagged api:a1b2c3d4

2026-06-25T01:13:00.000Z ✅ Pipeline completed successfully in 3m 0s
```

---

## 4. Log Formats

> Log format determines how log data is structured. Choosing the right format affects parsability, storage efficiency, and tooling compatibility.

---

### 4.1 Plain Text (Unstructured)

**Description**: Free-form text with no guaranteed structure.

**Example**:
```
[ERROR] 2026-06-25 01:10:05 - Connection to database failed after 3 retries
Stack trace:
  at DatabasePool.connect (db.js:45)
  at OrderService.createOrder (orders.js:123)
  at POST /api/orders (routes.js:67)
```

**Pros**: Human-readable, easy to write  
**Cons**: Hard to parse, inconsistent, poor for aggregation

---

### 4.2 JSON (Structured)

**Description**: Every field is a key-value pair in valid JSON.

**Example**:
```json
{
  "timestamp": "2026-06-25T01:10:05.123Z",
  "level": "ERROR",
  "service": "order-service",
  "version": "2.3.1",
  "environment": "production",
  "trace_id": "abc123def456",
  "span_id": "xyz789",
  "user_id": "USR-789",
  "message": "Database connection failed",
  "error": {
    "type": "ConnectionTimeoutError",
    "message": "Connection timeout after 5000ms",
    "stack": "Error: Connection timeout...\n  at Pool.connect (pool.js:45)"
  },
  "context": {
    "host": "api-pod-abc123",
    "attempt": 3,
    "max_attempts": 3,
    "duration_ms": 5023
  }
}
```

**Pros**: Machine-parseable, queryable, consistent, easy to filter  
**Cons**: More verbose, slightly harder to read by eye

---

### 4.3 Logfmt (Key=Value)

**Description**: A space-separated key=value format, popular in Go applications (Prometheus, Grafana).

**Example**:
```
time="2026-06-25T01:10:05Z" level=error service=order-service
  msg="Database connection failed" trace_id=abc123 user_id=USR-789
  attempt=3 duration_ms=5023 error="connection timeout"
```

**Pros**: Human-readable AND machine-parseable, compact  
**Cons**: Less standard than JSON, quoting rules can be tricky

---

### 4.4 Common Log Format (CLF) / Combined Log Format

**Description**: W3C standard format used by Apache/Nginx.

**CLF**:
```
%h %l %u %t "%r" %>s %b
```

**Combined (CLF + Referer + User-Agent)**:
```
127.0.0.1 - frank [25/Jun/2026:01:10:05 +0500] "GET /index.html HTTP/1.1" 200 2326 "http://example.com/" "Mozilla/5.0"
```

---

### 4.5 Syslog Format (RFC 3164 / RFC 5424)

**RFC 3164 (Legacy)**:
```
<34>Jun 25 01:10:05 server sshd[1234]: Accepted publickey for devops
```

**RFC 5424 (Modern)**:
```
<34>1 2026-06-25T01:10:05.003Z server sshd 1234 ID47 [exampleSDID@32473 iut="3" eventSource="Application"] Accepted publickey for devops
```

**Syslog Priority Calculation**:
```
Priority = (Facility × 8) + Severity

Facilities:
  0  = kernel
  1  = user
  3  = system daemons
  4  = security/auth
  16 = local0 ... 23 = local7

Example: auth facility(4) + error severity(3) = 4×8+3 = 35
<35>Jun 25 01:10:05 server sshd: Authentication failure
```

---

### 4.6 CEF (Common Event Format)

**Description**: Used by SIEM systems (ArcSight, Splunk). Standardized security event format.

**Format**:
```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

**Example**:
```
CEF:0|Palo Alto Networks|Firewall|9.1|200001|TRAFFIC ALLOW|3|
  src=10.0.0.5 dst=8.8.8.8 spt=54321 dpt=443 proto=TCP
  act=allow app=ssl cs1Label=policy cs1=outbound-https
  rt=1719274205000 deviceExternalId=PA-FW-01
```

---

### 4.7 GELF (Graylog Extended Log Format)

**Description**: JSON-based format designed for Graylog, supports chunked UDP messages.

**Example**:
```json
{
  "version": "1.1",
  "host": "api-server-01",
  "short_message": "Database connection failed",
  "full_message": "Detailed error with stack trace...",
  "timestamp": 1719274205.123,
  "level": 3,
  "_service": "order-service",
  "_trace_id": "abc123def456",
  "_user_id": "USR-789",
  "_duration_ms": 5023
}
```

---

### 4.8 W3C Extended Log Format (IIS / CDN)

**Example (Azure CDN / IIS)**:
```
#Version: 1.0
#Date: 2026-06-25 01:10:05
#Fields: date time s-ip cs-method cs-uri-stem sc-status sc-bytes cs-bytes time-taken cs(User-Agent)
2026-06-25 01:10:05 10.0.0.5 GET /api/orders 200 485 342 145 Mozilla/5.0
```

---

## 5. Structured vs Unstructured Logging

### Comparison

| Aspect | Unstructured | Structured (JSON) |
|---|---|---|
| Human readability | ✅ Easy | ⚠️ Harder without tooling |
| Machine parseability | ❌ Requires regex | ✅ Native parsing |
| Query performance | ❌ Slow (full-text scan) | ✅ Fast (field-based) |
| Storage efficiency | ✅ Smaller | ❌ Larger (key overhead) |
| Alerting reliability | ❌ Fragile regex | ✅ Exact field matching |
| Schema evolution | ✅ No schema | ⚠️ Schema changes need care |
| Cost (Splunk/Datadog) | ❌ More expensive | ✅ Field filtering possible |
| Tooling support | ⚠️ Varies | ✅ Universal |

### Migration: Unstructured → Structured

**Before (unstructured)**:
```
ERROR 2026-06-25 01:10:05 - Order ORD-12345 payment failed: card declined for user USR-789 (amount: $99.99)
```

**After (structured JSON)**:
```json
{
  "timestamp": "2026-06-25T01:10:05.123Z",
  "level": "ERROR",
  "event": "payment_failed",
  "order_id": "ORD-12345",
  "user_id": "USR-789",
  "amount": 99.99,
  "currency": "USD",
  "failure_reason": "card_declined",
  "service": "payment-service",
  "trace_id": "abc123"
}
```

**Benefit**: Now you can query:
```sql
-- Find all card declines in last hour
SELECT count(*) WHERE event="payment_failed" AND failure_reason="card_declined"

-- Average amount of failed payments by reason
SELECT failure_reason, avg(amount), count(*) GROUP BY failure_reason
```

---

## 6. Log Collection & Shipping

> Log shippers are agents that read logs from various sources and forward them to a central aggregator.

---

### 6.1 Filebeat (Elastic)

**Description**: Lightweight log shipper from Elastic. Reads log files and ships to Elasticsearch/Logstash/Kafka.

**Configuration** (`filebeat.yml`):
```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/nginx/access.log
      - /var/log/nginx/error.log
    fields:
      service: nginx
      environment: production
    fields_under_root: true
    multiline.pattern: '^[[:space:]]+(at|\.{3})[[:space:]]+\b|^Caused by:'
    multiline.negate: false
    multiline.match: after

  - type: log
    paths:
      - /var/log/app/*.log
    fields:
      service: api-service
    json.keys_under_root: true
    json.overwrite_keys: true

filebeat.modules:
  - module: system
    syslog:
      enabled: true
    auth:
      enabled: true

output.logstash:
  hosts: ["logstash:5044"]
  loadbalance: true
  ssl.certificate_authorities: ["/etc/ssl/ca.crt"]

# OR output to Elasticsearch directly
output.elasticsearch:
  hosts: ["https://elasticsearch:9200"]
  username: "filebeat_writer"
  password: "${ELASTICSEARCH_PASSWORD}"
  index: "filebeat-%{[agent.version]}-%{+yyyy.MM.dd}"

processors:
  - add_host_metadata: ~
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
  - add_kubernetes_metadata:
      host: ${NODE_NAME}
      matchers:
        - logs_path:
            logs_path: "/var/log/containers/"
```

---

### 6.2 Fluent Bit (Lightweight)

**Description**: Extremely lightweight (< 1MB memory), high-performance log processor and forwarder. Default in many Kubernetes setups.

**Configuration** (`fluent-bit.conf`):
```ini
[SERVICE]
    Flush         5
    Daemon        Off
    Log_Level     info
    Parsers_File  parsers.conf
    HTTP_Server   On
    HTTP_Listen   0.0.0.0
    HTTP_Port     2020

[INPUT]
    Name              tail
    Path              /var/log/containers/*.log
    Parser            docker
    Tag               kube.*
    Refresh_Interval  5
    Mem_Buf_Limit     5MB
    Skip_Long_Lines   On

[INPUT]
    Name   systemd
    Tag    host.*
    Strip_Underscores On

[FILTER]
    Name                kubernetes
    Match               kube.*
    Kube_URL            https://kubernetes.default.svc:443
    Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token
    Merge_Log           On
    K8S-Logging.Parser  On
    K8S-Logging.Exclude On
    Annotations         Off
    Labels              On

[FILTER]
    Name   grep
    Match  *
    Exclude log health

[OUTPUT]
    Name            es
    Match           *
    Host            elasticsearch
    Port            9200
    Logstash_Format On
    Logstash_Prefix logs
    Include_Tag_Key On
    Tag_Key         @log_name
    Retry_Limit     5

[OUTPUT]
    Name    loki
    Match   kube.*
    Host    loki
    Port    3100
    Labels  job=fluentbit, node=$NODE_NAME
    Auto_Kubernetes_Labels On
```

**Parsers** (`parsers.conf`):
```ini
[PARSER]
    Name        docker
    Format      json
    Time_Key    time
    Time_Format %Y-%m-%dT%H:%M:%S.%L
    Time_Keep   On

[PARSER]
    Name        nginx_access
    Format      regex
    Regex       ^(?<remote>[^ ]*) (?<host>[^ ]*) (?<user>[^ ]*) \[(?<time>[^\]]*)\] "(?<method>\S+)(?: +(?<path>[^\"]*?)(?: +\S*)?)?" (?<code>[^ ]*) (?<size>[^ ]*)(?: "(?<referer>[^\"]*)" "(?<agent>[^\"]*)")?$
    Time_Key    time
    Time_Format %d/%b/%Y:%H:%M:%S %z

[PARSER]
    Name        json_with_time
    Format      json
    Time_Key    timestamp
    Time_Format %Y-%m-%dT%H:%M:%S.%LZ
```

---

### 6.3 Fluentd (Full-Featured)

**Description**: Full-featured log aggregator and processor. More powerful than Fluent Bit but heavier.

**Configuration** (`fluentd.conf`):
```xml
<source>
  @type forward
  port 24224
  bind 0.0.0.0
</source>

<source>
  @type tail
  path /var/log/nginx/access.log
  pos_file /var/log/fluentd/nginx-access.log.pos
  tag nginx.access
  <parse>
    @type nginx
  </parse>
</source>

<filter kube.**>
  @type kubernetes_metadata
  @id filter_kube_metadata
  kubernetes_url "https://#{ENV['KUBERNETES_SERVICE_HOST']}:#{ENV['KUBERNETES_SERVICE_PORT']}"
  verify_ssl true
  ca_file /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  skip_labels false
  skip_container_metadata false
  skip_master_url false
  skip_namespace_metadata false
</filter>

<filter **>
  @type record_transformer
  <record>
    hostname "#{Socket.gethostname}"
    environment "#{ENV['ENVIRONMENT']}"
  </record>
</filter>

<match nginx.access>
  @type elasticsearch
  host elasticsearch
  port 9200
  index_name nginx-access-%Y.%m.%d
  <buffer tag,time>
    @type file
    path /var/log/fluentd/buffer/nginx
    flush_mode interval
    flush_interval 10s
    chunk_limit_size 10m
    retry_max_times 3
    retry_wait 30s
  </buffer>
</match>
```

---

### 6.4 Vector (Modern, Rust-based)

**Description**: High-performance observability pipeline written in Rust. Can collect, transform, and route logs, metrics, and traces.

**Configuration** (`vector.toml`):
```toml
[sources.app_logs]
  type = "file"
  include = ["/var/log/app/*.log"]
  read_from = "beginning"

[sources.journald]
  type = "journald"
  current_boot_only = true

[sources.kubernetes_logs]
  type = "kubernetes_logs"

[transforms.parse_json]
  type = "remap"
  inputs = ["app_logs"]
  source = '''
    . = parse_json!(.message)
    .parsed_at = now()
  '''

[transforms.filter_noise]
  type = "filter"
  inputs = ["parse_json"]
  condition = '.level != "DEBUG" && .message != "/health"'

[transforms.enrich]
  type = "remap"
  inputs = ["filter_noise"]
  source = '''
    .environment = get_env_var!("ENVIRONMENT")
    .datacenter = "us-east-1"
  '''

[sinks.elasticsearch]
  type = "elasticsearch"
  inputs = ["enrich"]
  endpoint = "https://elasticsearch:9200"
  index = "logs-%Y-%m-%d"
  auth.strategy = "basic"
  auth.user = "vector"
  auth.password = "${ELASTICSEARCH_PASSWORD}"
  bulk.action = "index"

[sinks.loki]
  type = "loki"
  inputs = ["kubernetes_logs"]
  endpoint = "http://loki:3100"
  labels.job = "vector"
  labels.node = "{{ kubernetes.pod_node_name }}"
  encoding.codec = "json"

[sinks.s3_archive]
  type = "aws_s3"
  inputs = ["enrich"]
  bucket = "my-log-archive"
  region = "us-east-1"
  key_prefix = "logs/{{ .environment }}/%Y/%m/%d/"
  encoding.codec = "ndjson"
  compression = "gzip"
```

---

### 6.5 Log Shipper Comparison

| Feature | Filebeat | Fluent Bit | Fluentd | Vector |
|---|---|---|---|---|
| Language | Go | C | Ruby | Rust |
| Memory (idle) | ~30MB | ~1MB | ~40MB | ~10MB |
| Throughput | High | Very High | High | Very High |
| CPU overhead | Low | Very Low | Moderate | Very Low |
| Config complexity | Medium | Medium | Complex | Medium |
| Plugin ecosystem | Elastic focused | Limited | Vast | Growing |
| K8s default | No | ✅ Yes (many distros) | No | No |
| Multi-pipeline | No | Limited | Yes | Yes |
| Built-in transforms | Basic | Basic | Rich | Rich |
| Best for | ELK stack | K8s, IoT, edge | Complex routing | Modern pipelines |

---

## 7. Log Aggregation & Storage

> Centralized log storage is essential for searching across many services and machines simultaneously.

---

### 7.1 Elasticsearch

**Description**: Distributed search and analytics engine. The "E" in ELK stack.

**Index Management**:
```json
// Index template
PUT _index_template/logs-template
{
  "index_patterns": ["logs-*"],
  "template": {
    "settings": {
      "number_of_shards": 3,
      "number_of_replicas": 1,
      "index.refresh_interval": "5s",
      "index.lifecycle.name": "logs-policy",
      "index.codec": "best_compression"
    },
    "mappings": {
      "properties": {
        "@timestamp":    { "type": "date" },
        "level":         { "type": "keyword" },
        "service":       { "type": "keyword" },
        "trace_id":      { "type": "keyword" },
        "message":       { "type": "text", "analyzer": "standard" },
        "duration_ms":   { "type": "long" },
        "status_code":   { "type": "integer" },
        "user_id":       { "type": "keyword" },
        "environment":   { "type": "keyword" }
      }
    }
  }
}
```

**ILM (Index Lifecycle Management)**:
```json
PUT _ilm/policy/logs-policy
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_age": "1d",
            "max_size": "50gb",
            "max_docs": 100000000
          },
          "set_priority": { "priority": 100 }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "shrink": { "number_of_shards": 1 },
          "forcemerge": { "max_num_segments": 1 },
          "set_priority": { "priority": 50 }
        }
      },
      "cold": {
        "min_age": "30d",
        "actions": {
          "freeze": {},
          "set_priority": { "priority": 0 }
        }
      },
      "delete": {
        "min_age": "90d",
        "actions": { "delete": {} }
      }
    }
  }
}
```

---

### 7.2 Grafana Loki

**Description**: Log aggregation system designed to be cost-effective. Does NOT index log content — only indexes metadata labels. Logs are stored as compressed chunks.

**Key Difference from Elasticsearch**:
```
Elasticsearch: Indexes all fields → Fast search, high cost
Loki:          Indexes only labels → Cheaper, slightly slower full-text search
```

**Label Strategy**:
```yaml
# Good labels (low cardinality)
{
  job="nginx",
  environment="production",
  cluster="us-east-1",
  namespace="payments"
}

# Bad labels (high cardinality - NEVER do this)
{
  user_id="USR-789",         # Millions of unique values!
  request_id="abc123def456",  # Every request is unique!
  ip_address="10.0.0.5"      # Too many unique values
}
```

**LogQL Queries**:
```logql
# Basic label filter
{job="nginx", environment="production"}

# Filter log lines
{job="nginx"} |= "ERROR"

# Exclude health checks
{job="nginx"} != "/health"

# Regex filter
{job="api-service"} |~ "payment.*failed"

# Parse JSON logs and filter
{job="api-service"} | json | level="ERROR"

# Extract fields and aggregate
{job="nginx"} | pattern `<ip> - - [<_>] "<method> <uri> HTTP/<_>" <status> <_>`
| status >= 500
| line_format "{{.method}} {{.uri}} -> {{.status}}"

# Count error rate
sum(rate({job="api-service"} |= "ERROR" [5m])) by (service)

# Latency percentile from logs
{job="api-service"} | json | unwrap duration_ms | quantile_over_time(0.99, [5m]) by (service)
```

---

### 7.3 Splunk

**Description**: Enterprise-grade SIEM and log analytics platform. Industry standard for security.

**Splunk Search Processing Language (SPL)**:
```splunk
# Basic search
index=production sourcetype=nginx level=ERROR

# Time-based search with stats
index=production sourcetype=app level=ERROR
| timechart span=5m count by service

# Top errors by service
index=production level=ERROR
| stats count by service, error_type
| sort -count
| head 10

# Slow requests analysis
index=production sourcetype=nginx
| rex field=_raw "rt=(?<request_time>\d+\.\d+)"
| eval rt_ms = request_time * 1000
| stats avg(rt_ms), p95(rt_ms), p99(rt_ms), max(rt_ms) by uri

# Security: brute force detection
index=auth action=failure
| bucket _time span=5m
| stats count by src_ip, _time
| where count > 10
| sort -count
```

---

### 7.4 CloudWatch Logs

**Description**: AWS native log storage. Tight integration with all AWS services.

**Key Concepts**:
```
Log Group:  Container for log streams (e.g., /aws/lambda/my-function)
Log Stream: Sequence of log events from one source (e.g., one Lambda instance)
Log Event:  Single log entry with timestamp and message
```

**CloudWatch Logs Insights Queries**:
```sql
-- Find errors in last hour
fields @timestamp, @message
| filter @message like /ERROR/
| sort @timestamp desc
| limit 100

-- Count by log level
fields @timestamp, level
| stats count() by level
| sort count desc

-- Slow Lambda executions
filter @type = "REPORT"
| fields @requestId, @duration, @billedDuration, @memorySize, @maxMemoryUsed
| filter @duration > 3000
| sort @duration desc

-- API error rate over time
fields @timestamp, status
| filter status >= 500
| stats count() as errors by bin(5m)
| sort @timestamp

-- User authentication failures
fields @timestamp, user, sourceIPAddress, errorCode
| filter eventName = "ConsoleLogin" and errorMessage = "Failed authentication"
| stats count() by user, sourceIPAddress
| sort count desc
```

---

### 7.5 Log Storage Comparison

| Platform | Storage Type | Indexing | Cost Model | Best For |
|---|---|---|---|---|
| **Elasticsearch** | Full-text index | All fields | Pay per GB stored + compute | Rich search, analytics |
| **Loki** | Compressed chunks | Labels only | Much cheaper | Kubernetes, cost-conscious |
| **Splunk** | Proprietary index | All fields | License per GB/day | Enterprise SIEM |
| **CloudWatch** | AWS proprietary | Full-text | Pay per GB ingested + scanned | AWS-native workloads |
| **Datadog Logs** | Proprietary | Indexed fields | Per GB ingested | Full-stack observability |
| **Graylog** | Elasticsearch | All fields | Open source + enterprise | Self-hosted alternative |
| **S3 (archive)** | Object storage | None (manual) | Cheapest possible | Long-term compliance |

---

## 8. Log Parsing & Processing

> Raw logs are rarely in the perfect format. Parsing transforms raw text into structured, queryable fields.

---

### 8.1 Grok Patterns (Logstash)

**Description**: Grok is a pattern-matching language for extracting structured fields from unstructured text.

**Built-in Patterns**:
```
%{IP}           → Matches IPv4/IPv6 addresses
%{NUMBER}       → Matches integers and floats
%{WORD}         → Matches word characters
%{DATA}         → Matches any data (greedy)
%{GREEDYDATA}   → Like DATA but more greedy
%{TIMESTAMP_ISO8601} → ISO 8601 timestamps
%{HTTPDATE}     → Apache/Nginx timestamp format
```

**Parsing Nginx Access Logs**:
```ruby
# Logstash grok filter
filter {
  grok {
    match => {
      "message" => '%{IPORHOST:client_ip} - %{DATA:user} \[%{HTTPDATE:timestamp}\] "%{WORD:method} %{DATA:uri} HTTP/%{NUMBER:http_version}" %{NUMBER:status_code:int} %{NUMBER:bytes_sent:int} "%{DATA:referrer}" "%{DATA:user_agent}" rt=%{NUMBER:request_time:float}'
    }
  }

  date {
    match => ["timestamp", "dd/MMM/yyyy:HH:mm:ss Z"]
    target => "@timestamp"
  }

  if [status_code] >= 500 {
    mutate { add_tag => ["server_error"] }
  }

  geoip {
    source => "client_ip"
    target => "geoip"
  }

  useragent {
    source => "user_agent"
    target => "ua"
  }
}
```

---

### 8.2 Regular Expressions for Log Parsing

**Common Patterns**:
```python
import re

# Extract IP addresses
ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

# Extract timestamps (ISO 8601)
ts_pattern = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?'

# Extract HTTP status codes
status_pattern = r'\b[1-5]\d{2}\b'

# Extract duration values (e.g., "duration=145ms" or "rt=0.145")
duration_pattern = r'(?:duration|rt|latency)[=: ]+(\d+(?:\.\d+)?)'

# Extract key=value pairs (logfmt)
logfmt_pattern = r'(\w+)=(?:"([^"]*)"|([\w./:-]+))'

# Parse a complete log line
nginx_log_pattern = r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<uri>\S+) HTTP/\S+" (?P<status>\d+) (?P<bytes>\d+)'

log_line = '192.168.1.1 - john [25/Jun/2026:01:10:05 +0000] "POST /api/orders HTTP/1.1" 201 485'
match = re.match(nginx_log_pattern, log_line)
if match:
    print(match.groupdict())
# Output:
# {'ip': '192.168.1.1', 'user': 'john', 'time': '25/Jun/2026:01:10:05 +0000',
#  'method': 'POST', 'uri': '/api/orders', 'status': '201', 'bytes': '485'}
```

---

### 8.3 Logstash Pipeline

**Complete Pipeline Example**:
```ruby
# /etc/logstash/pipeline/main.conf

input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/ssl/logstash.crt"
    ssl_key => "/etc/ssl/logstash.key"
  }

  kafka {
    bootstrap_servers => "kafka:9092"
    topics => ["application-logs", "system-logs"]
    group_id => "logstash-consumers"
    codec => json
  }
}

filter {
  # Add ingestion timestamp
  ruby {
    code => "event.set('ingested_at', Time.now.utc.iso8601(3))"
  }

  # Parse JSON app logs
  if [fields][log_type] == "application" {
    json {
      source => "message"
      target => "app"
    }
    date {
      match => ["[app][timestamp]", "ISO8601"]
      target => "@timestamp"
    }
    mutate {
      rename => { "[app][level]" => "level" }
      rename => { "[app][service]" => "service" }
      rename => { "[app][trace_id]" => "trace_id" }
      rename => { "[app][message]" => "log_message" }
    }
  }

  # Parse Nginx access logs
  if [fields][log_type] == "nginx_access" {
    grok {
      match => { "message" => "%{COMBINEDAPACHELOG}" }
    }
    mutate {
      convert => { "response" => "integer" }
      convert => { "bytes" => "integer" }
    }
  }

  # GeoIP enrichment
  if [client_ip] and [client_ip] !~ /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/ {
    geoip {
      source => "client_ip"
      target => "geoip"
      fields => ["city_name", "country_code2", "latitude", "longitude"]
    }
  }

  # Drop health check logs
  if [request] =~ /GET \/health/ or [request] =~ /GET \/ping/ {
    drop {}
  }

  # Mask sensitive data
  mutate {
    gsub => [
      "message", '"password"\s*:\s*"[^"]*"', '"password": "***REDACTED***"',
      "message", '\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', '****-****-****-****'
    ]
  }
}

output {
  elasticsearch {
    hosts => ["https://elasticsearch:9200"]
    user => "logstash_writer"
    password => "${ES_PASSWORD}"
    index => "logs-%{[service]}-%{+YYYY.MM.dd}"
    document_type => "_doc"
    ilm_enabled => true
    ilm_rollover_alias => "logs"
    ilm_policy => "logs-policy"
  }

  # Dead letter queue for failed events
  if "_grokparsefailure" in [tags] or "_jsonparsefailure" in [tags] {
    elasticsearch {
      hosts => ["https://elasticsearch:9200"]
      index => "failed-logs-%{+YYYY.MM.dd}"
    }
  }
}
```

---

### 8.4 Log Enrichment

**Definition**: Adding additional context to log events during processing.

**Common Enrichments**:
```
1. GeoIP Lookup:      IP address → Country, City, Lat/Long
2. DNS Lookup:        IP → Hostname
3. User-Agent Parse:  UA string → Browser, OS, Device type
4. Kubernetes Metadata: Pod name → Namespace, Labels, Deployment
5. Cloud Metadata:    Instance ID → Region, AZ, Instance type
6. Threat Intelligence: IP → Known malicious/VPN/TOR exit node
7. Service Discovery: service name → Team, Tier, SLO target
```

**Kubernetes Metadata Enrichment**:
```json
// Before enrichment
{
  "log": "ERROR: Database connection failed",
  "container_id": "a1b2c3d4e5f6"
}

// After kubernetes_metadata filter
{
  "log": "ERROR: Database connection failed",
  "container_id": "a1b2c3d4e5f6",
  "kubernetes": {
    "pod_name": "api-service-7d4f8b9c6-xkj2p",
    "namespace_name": "production",
    "labels": {
      "app": "api-service",
      "version": "2.3.1",
      "team": "backend"
    },
    "node_name": "ip-10-0-1-50.ec2.internal",
    "container_name": "api-service"
  }
}
```

---

## 9. Log Analysis & Search

---

### 9.1 Kibana Query Language (KQL)

```kql
# Simple field search
service: "api-service"

# AND conditions
service: "api-service" AND level: "ERROR"

# OR conditions
level: "ERROR" OR level: "CRITICAL"

# Wildcard
service: api-*

# Range query
duration_ms > 1000

# Range with AND
duration_ms >= 500 AND status_code: 200

# Text contains
message: "database connection"

# Phrase match
message: "connection timeout"

# Negation
NOT level: "DEBUG"

# Nested field
kubernetes.namespace: "production" AND level: "ERROR"

# Time range (use Kibana date picker or):
@timestamp >= "2026-06-25T00:00:00Z" AND @timestamp < "2026-06-25T01:00:00Z"
```

---

### 9.2 Elasticsearch Query DSL

```json
// Find all errors with slow response in last hour
GET logs-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "level": "ERROR" } },
        { "range": { "duration_ms": { "gte": 1000 } } }
      ],
      "filter": [
        { "range": { "@timestamp": { "gte": "now-1h", "lte": "now" } } }
      ],
      "must_not": [
        { "term": { "service": "health-checker" } }
      ]
    }
  },
  "aggs": {
    "errors_by_service": {
      "terms": { "field": "service", "size": 10 }
    },
    "errors_over_time": {
      "date_histogram": {
        "field": "@timestamp",
        "fixed_interval": "5m"
      }
    },
    "avg_duration": {
      "avg": { "field": "duration_ms" }
    },
    "p99_duration": {
      "percentiles": {
        "field": "duration_ms",
        "percents": [50, 95, 99]
      }
    }
  },
  "sort": [{ "@timestamp": "desc" }],
  "size": 100
}
```

---

### 9.3 Common Log Analysis Patterns

**Error Rate Trend**:
```sql
-- Kibana Lens / Elasticsearch aggregation
SELECT
  date_trunc('5 minutes', @timestamp) as time_bucket,
  service,
  count(*) as total_requests,
  sum(CASE WHEN level = 'ERROR' THEN 1 ELSE 0 END) as error_count,
  sum(CASE WHEN level = 'ERROR' THEN 1 ELSE 0 END) * 100.0 / count(*) as error_rate_pct
FROM logs
WHERE @timestamp >= now() - interval '1 hour'
GROUP BY 1, 2
ORDER BY 1, error_rate_pct DESC
```

**Top Slow Endpoints**:
```sql
SELECT
  uri,
  count(*) as request_count,
  percentile_cont(0.50) WITHIN GROUP (ORDER BY duration_ms) as p50,
  percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) as p95,
  percentile_cont(0.99) WITHIN GROUP (ORDER BY duration_ms) as p99,
  max(duration_ms) as max_ms
FROM nginx_logs
WHERE @timestamp >= now() - interval '1 hour'
GROUP BY uri
HAVING count(*) > 10
ORDER BY p99 DESC
LIMIT 20
```

**Unique Error Messages (deduplication)**:
```sql
-- Find distinct error patterns, excluding noise
SELECT
  message_template,
  count(*) as occurrences,
  min(@timestamp) as first_seen,
  max(@timestamp) as last_seen,
  array_agg(DISTINCT service) as affected_services
FROM logs
WHERE level IN ('ERROR', 'CRITICAL')
  AND @timestamp >= now() - interval '1 hour'
GROUP BY message_template
ORDER BY occurrences DESC
```

---

## 10. Log Monitoring & Alerting

---

### 10.1 Alert Types

| Alert Type | Description | Example |
|---|---|---|
| **Threshold** | Trigger when count exceeds N | > 10 errors in 5 min |
| **Rate-based** | Trigger on rate of change | Error rate > 1% |
| **Absence** | Trigger when expected logs stop | No heartbeat log in 5 min |
| **Pattern** | Trigger on specific text/pattern | "OOMKilled" appears |
| **Anomaly** | Trigger on statistical deviation | 3x normal error rate |
| **Compound** | Multiple conditions combined | Error rate > 1% AND > 100 errors |

---

### 10.2 Elasticsearch Watcher / Kibana Alerts

```json
// Alert: Error rate exceeds 1% in 5 minute window
PUT _watcher/watch/high-error-rate
{
  "trigger": {
    "schedule": { "interval": "1m" }
  },
  "input": {
    "search": {
      "request": {
        "indices": ["logs-*"],
        "body": {
          "query": {
            "range": { "@timestamp": { "gte": "now-5m" } }
          },
          "aggs": {
            "total": { "value_count": { "field": "@timestamp" } },
            "errors": {
              "filter": { "term": { "level": "ERROR" } }
            }
          },
          "size": 0
        }
      }
    }
  },
  "condition": {
    "script": {
      "source": """
        def total = ctx.payload.aggregations.total.value;
        def errors = ctx.payload.aggregations.errors.doc_count;
        if (total == 0) return false;
        return (errors / total) > 0.01;
      """
    }
  },
  "actions": {
    "slack_notification": {
      "webhook": {
        "scheme": "https",
        "host": "hooks.slack.com",
        "path": "/services/YOUR/SLACK/WEBHOOK",
        "method": "post",
        "body": "{\"text\": \"🚨 Error rate exceeded 1% threshold\"}"
      }
    }
  }
}
```

---

### 10.3 Grafana Loki Alerting Rules

```yaml
# Grafana alerting rule for log-based alerts
groups:
  - name: log-alerts
    rules:
      - alert: HighErrorRate
        expr: |
          sum(rate({job="api-service"} |= "ERROR" [5m])) by (service)
          /
          sum(rate({job="api-service"} [5m])) by (service)
          > 0.01
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected in {{ $labels.service }}"
          description: "Error rate is {{ $value | humanizePercentage }} in the last 5 minutes"

      - alert: NoLogsReceived
        expr: |
          absent(rate({job="api-service"}[5m]))
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "No logs received from api-service"
          description: "api-service has stopped sending logs for 5+ minutes"

      - alert: CriticalLogPattern
        expr: |
          count_over_time({job="api-service"} |= "FATAL" [1m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "FATAL error detected"
```

---

### 10.4 CloudWatch Metric Filters

```json
// Create a metric filter to count ERROR logs
{
  "filterPattern": "{ $.level = \"ERROR\" }",
  "metricTransformations": [
    {
      "metricName": "ApplicationErrorCount",
      "metricNamespace": "AppMetrics",
      "metricValue": "1",
      "defaultValue": 0,
      "unit": "Count",
      "dimensions": {
        "Service": "$.service",
        "Environment": "$.environment"
      }
    }
  ]
}

// Alert on the metric
{
  "AlarmName": "HighErrorRate",
  "ComparisonOperator": "GreaterThanThreshold",
  "EvaluationPeriods": 2,
  "MetricName": "ApplicationErrorCount",
  "Namespace": "AppMetrics",
  "Period": 300,
  "Statistic": "Sum",
  "Threshold": 10,
  "AlarmActions": ["arn:aws:sns:us-east-1:123456:alerts"],
  "TreatMissingData": "notBreaching"
}
```

---

## 11. Application Logging Best Practices

---

### 11.1 What to Log (and What NOT to)

**✅ Always Log**:
```
- Application startup/shutdown events
- Configuration changes and reloads
- Authentication events (success and failure)
- Authorization denials
- Significant business events (order created, payment processed)
- All errors and exceptions with full stack trace
- Slow operations (DB queries > threshold, API calls > threshold)
- External service calls (start + result)
- User actions in critical paths
- Resource exhaustion warnings
```

**❌ Never Log**:
```
- Passwords (even hashed)
- Credit card numbers (even masked partially)
- Social Security / National ID numbers
- Private keys or secrets
- Full JWT tokens or session tokens
- Personal health information (HIPAA)
- Personal data without consent (GDPR)
- Encryption keys
- Raw SQL with user data embedded
```

**⚠️ Log with Care (anonymize/mask)**:
```
- Email addresses → hash or truncate
- Phone numbers → mask to last 4 digits
- IP addresses → hash if PII, or just log country
- User IDs → OK if non-PII internal IDs
- Financial amounts → OK for business events
```

---

### 11.2 Log Correlation with Trace IDs

**Purpose**: Link all log entries from a single request across multiple services.

**Implementation (Node.js)**:
```javascript
const { v4: uuidv4 } = require('uuid');
const { AsyncLocalStorage } = require('async_hooks');

const asyncLocalStorage = new AsyncLocalStorage();

// Middleware: assign trace ID at request entry
app.use((req, res, next) => {
  const traceId = req.headers['x-trace-id'] || uuidv4();
  const store = { traceId, userId: null };
  
  res.setHeader('x-trace-id', traceId);
  asyncLocalStorage.run(store, next);
});

// Logger that auto-includes trace ID
const logger = {
  info: (message, fields = {}) => {
    const store = asyncLocalStorage.getStore() || {};
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      level: 'INFO',
      message,
      trace_id: store.traceId,
      user_id: store.userId,
      service: 'api-service',
      ...fields
    }));
  },
  error: (message, error, fields = {}) => {
    const store = asyncLocalStorage.getStore() || {};
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      level: 'ERROR',
      message,
      trace_id: store.traceId,
      error: {
        type: error.constructor.name,
        message: error.message,
        stack: error.stack
      },
      service: 'api-service',
      ...fields
    }));
  }
};

// Usage
app.post('/api/orders', async (req, res) => {
  logger.info('Order creation started', { order_id: req.body.orderId });
  
  try {
    const order = await createOrder(req.body);
    logger.info('Order created successfully', {
      order_id: order.id,
      amount: order.amount,
      duration_ms: Date.now() - startTime
    });
    res.json(order);
  } catch (err) {
    logger.error('Order creation failed', err, {
      order_id: req.body.orderId,
      duration_ms: Date.now() - startTime
    });
    res.status(500).json({ error: 'Internal server error' });
  }
});
```

**Python (structlog)**:
```python
import structlog
import uuid
from contextvars import ContextVar

trace_id_var: ContextVar[str] = ContextVar('trace_id', default='')

def add_trace_id(logger, method, event_dict):
    event_dict['trace_id'] = trace_id_var.get('')
    return event_dict

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt='iso'),
        add_trace_id,
        structlog.processors.JSONRenderer()
    ]
)

log = structlog.get_logger()

# Middleware
@app.middleware("http")
async def trace_middleware(request: Request, call_next):
    trace_id = request.headers.get("x-trace-id", str(uuid.uuid4()))
    token = trace_id_var.set(trace_id)
    try:
        response = await call_next(request)
        response.headers["x-trace-id"] = trace_id
        return response
    finally:
        trace_id_var.reset(token)

# Usage
log.info("order_created", order_id="ORD-12345", amount=99.99)
# Output: {"event": "order_created", "order_id": "ORD-12345", "amount": 99.99, "trace_id": "abc123", ...}
```

---

### 11.3 Log Sampling

**Purpose**: Reduce log volume for high-frequency, low-value events.

**Strategies**:
```python
import random
import time

class SampledLogger:
    def __init__(self, logger, sample_rate=0.1):
        self.logger = logger
        self.sample_rate = sample_rate  # Log 10% of events
    
    def debug_sampled(self, message, **kwargs):
        if random.random() < self.sample_rate:
            self.logger.debug(message, **kwargs)
    
    def adaptive_sample(self, message, error_count, total_count, **kwargs):
        """Log more when error rate is high"""
        error_rate = error_count / max(total_count, 1)
        effective_rate = min(1.0, self.sample_rate + error_rate)
        
        if random.random() < effective_rate:
            self.logger.info(message, sample_rate=effective_rate, **kwargs)

# Rate-limited logging (max N logs per time window)
class RateLimitedLogger:
    def __init__(self, logger, max_per_second=10):
        self.logger = logger
        self.max_per_second = max_per_second
        self.count = 0
        self.window_start = time.time()
    
    def warn(self, message, **kwargs):
        now = time.time()
        if now - self.window_start >= 1.0:
            self.count = 0
            self.window_start = now
        
        if self.count < self.max_per_second:
            self.count += 1
            self.logger.warn(message, **kwargs)
        # Silently drop if over rate limit
```

---

### 11.4 Log Format Standards (12-Factor App)

**The Twelve-Factor App recommends**:
1. Treat logs as event streams
2. Write all logs to `stdout` / `stderr`
3. Never manage log files within the application
4. Let the execution environment handle collection and routing

```
Application
    │ stdout (logs)
    │ stderr (errors)
    ▼
Process Supervisor / Container Runtime
    │
    ▼
Log Router (Fluentd/Fluent Bit/Vector)
    │
    ▼
Log Aggregator (Loki/Elasticsearch/CloudWatch)
```

---

## 12. Docker & Container Logging

---

### 12.1 Docker Logging Drivers

**Default**: `json-file` — logs stored as JSON files on host

```bash
# View container logs
docker logs container_name
docker logs -f container_name          # Follow (live)
docker logs --tail 100 container_name  # Last 100 lines
docker logs --since 1h container_name  # Last 1 hour
docker logs --timestamps container_name

# Log file location (json-file driver)
/var/lib/docker/containers/<container-id>/<container-id>-json.log
```

**Available Docker Logging Drivers**:
| Driver | Description | Use Case |
|---|---|---|
| `json-file` | JSON files on disk (default) | Development, small scale |
| `journald` | Linux systemd journal | Linux hosts with systemd |
| `syslog` | System syslog server | Traditional Unix logging |
| `fluentd` | Fluentd/Fluent Bit directly | Kubernetes-like environments |
| `awslogs` | AWS CloudWatch Logs | AWS deployments |
| `gcplogs` | GCP Cloud Logging | GCP deployments |
| `splunk` | Splunk HTTP Event Collector | Splunk deployments |
| `gelf` | Graylog Extended Log Format | Graylog deployments |
| `local` | Compressed binary format | High-throughput, local only |
| `none` | Disable logging entirely | Batch jobs, security |

**Configure Logging Driver** (`docker-compose.yml`):
```yaml
version: "3.8"
services:
  api:
    image: api-service:latest
    logging:
      driver: "json-file"
      options:
        max-size: "100m"        # Rotate at 100MB
        max-file: "5"           # Keep 5 rotated files
        compress: "true"        # Compress rotated files
        labels: "service,env"
        env: "ENVIRONMENT,VERSION"
    labels:
      - "service=api-service"
    environment:
      - ENVIRONMENT=production

  # Using fluentd driver
  worker:
    image: worker:latest
    logging:
      driver: "fluentd"
      options:
        fluentd-address: "localhost:24224"
        tag: "worker.{{.Name}}"
        fluentd-async: "true"
        fluentd-buffer-limit: "10485760"  # 10MB buffer

  # Using CloudWatch (AWS)
  scheduler:
    image: scheduler:latest
    logging:
      driver: "awslogs"
      options:
        awslogs-group: "/myapp/scheduler"
        awslogs-region: "us-east-1"
        awslogs-stream: "{{.Name}}"
        awslogs-create-group: "true"
        awslogs-datetime-format: "%Y-%m-%dT%H:%M:%S"
```

**Global Docker Daemon Logging Config** (`/etc/docker/daemon.json`):
```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "3",
    "compress": "true"
  }
}
```

---

### 12.2 Container Log Rotation

**Why it matters**: Containers writing to `json-file` without limits can fill up the host disk.

```bash
# Check current log sizes
find /var/lib/docker/containers -name "*.log" -exec du -sh {} \; | sort -rh | head -20

# Truncate a log file (emergency)
truncate -s 0 /var/lib/docker/containers/<id>/<id>-json.log

# Logrotate config for Docker
# /etc/logrotate.d/docker-containers
/var/lib/docker/containers/*/*.log {
    rotate 5
    daily
    compress
    size=100M
    missingok
    delaycompress
    copytruncate
}
```

---

## 13. Kubernetes Logging Architecture

---

### 13.1 K8s Logging Patterns

**Pattern 1: Node-Level Logging Agent (Recommended)**
```
┌─────────────────────────────────────────────┐
│ Kubernetes Node                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  Pod A   │  │  Pod B   │  │  Pod C   │  │
│  │ stdout ──┼──┼─────────┼──┼─────────►│  │
│  └──────────┘  └──────────┘  └──────────┘  │
│                    ▼                         │
│         /var/log/containers/*.log            │
│                    ▼                         │
│  ┌─────────────────────────────────────────┐ │
│  │  DaemonSet: Fluent Bit / Filebeat       │ │
│  │  (one per node)                         │ │
│  └──────────────────┬──────────────────────┘ │
└─────────────────────┼───────────────────────┘
                       ▼
              Central Log Aggregator
              (Loki / Elasticsearch)
```

**Pattern 2: Sidecar Container**
```yaml
# Pod with sidecar logging agent
apiVersion: v1
kind: Pod
metadata:
  name: api-with-sidecar
spec:
  volumes:
    - name: app-logs
      emptyDir: {}

  containers:
    # Main application
    - name: api-service
      image: api-service:latest
      volumeMounts:
        - name: app-logs
          mountPath: /var/log/app

    # Sidecar: ships logs to central aggregator
    - name: log-shipper
      image: fluent/fluent-bit:latest
      volumeMounts:
        - name: app-logs
          mountPath: /var/log/app
          readOnly: true
      resources:
        requests:
          memory: "32Mi"
          cpu: "50m"
        limits:
          memory: "64Mi"
          cpu: "100m"
```

---

### 13.2 Fluent Bit DaemonSet (Kubernetes)

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluent-bit
  namespace: logging
  labels:
    app: fluent-bit
spec:
  selector:
    matchLabels:
      app: fluent-bit
  template:
    metadata:
      labels:
        app: fluent-bit
    spec:
      serviceAccountName: fluent-bit
      tolerations:
        - key: node-role.kubernetes.io/master
          effect: NoSchedule
      containers:
        - name: fluent-bit
          image: fluent/fluent-bit:2.2.0
          ports:
            - containerPort: 2020
              name: metrics
          resources:
            requests:
              memory: "64Mi"
              cpu: "100m"
            limits:
              memory: "128Mi"
              cpu: "200m"
          volumeMounts:
            - name: varlog
              mountPath: /var/log
              readOnly: true
            - name: varlibdockercontainers
              mountPath: /var/lib/docker/containers
              readOnly: true
            - name: etcmachineid
              mountPath: /etc/machine-id
              readOnly: true
            - name: fluent-bit-config
              mountPath: /fluent-bit/etc/
          env:
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: HOST_IP
              valueFrom:
                fieldRef:
                  fieldPath: status.hostIP
      volumes:
        - name: varlog
          hostPath:
            path: /var/log
        - name: varlibdockercontainers
          hostPath:
            path: /var/lib/docker/containers
        - name: etcmachineid
          hostPath:
            path: /etc/machine-id
            type: File
        - name: fluent-bit-config
          configMap:
            name: fluent-bit-config
```

---

### 13.3 Kubernetes Audit Logging Configuration

```yaml
# kube-apiserver audit policy
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Do not log requests to certain non-resource paths
  - level: None
    nonResourceURLs:
      - /healthz
      - /readyz
      - /livez
      - /metrics

  # Do not log watch requests by system components
  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
      - group: ""
        resources: ["endpoints", "services", "services/status"]

  # Log secret access at RequestResponse level (important for security)
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets", "configmaps"]

  # Log all pod exec/attach (high risk)
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "pods/portforward"]

  # Log all changes to RBAC
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]

  # Log all pod mutations
  - level: Request
    verbs: ["create", "update", "patch", "delete"]
    resources:
      - group: ""
        resources: ["pods"]

  # Default: log metadata only for everything else
  - level: Metadata
    omitStages:
      - RequestReceived
```

---

## 14. Cloud Provider Logging (AWS / GCP / Azure)

---

### 14.1 AWS CloudTrail

**Description**: Records every API call made to AWS services. Essential for security and compliance.

**Log Entry Example**:
```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDIODR4TAW7CSEXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/devops-engineer",
    "accountId": "123456789012",
    "userName": "devops-engineer"
  },
  "eventTime": "2026-06-25T01:10:05Z",
  "eventSource": "ec2.amazonaws.com",
  "eventName": "TerminateInstances",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "10.0.0.5",
  "userAgent": "aws-cli/2.0.0",
  "requestParameters": {
    "instancesSet": {
      "items": [{ "instanceId": "i-1234567890abcdef0" }]
    }
  },
  "responseElements": {
    "instancesSet": {
      "items": [{
        "instanceId": "i-1234567890abcdef0",
        "currentState": { "code": 32, "name": "shutting-down" },
        "previousState": { "code": 16, "name": "running" }
      }]
    }
  }
}
```

**Key CloudTrail Use Cases**:
```
Security:
  - Who deleted that S3 bucket?
  - Who modified the IAM role?
  - Which IP address made this API call?
  - Was there any console login from outside corporate IPs?

Operations:
  - What changed before the outage?
  - Who last modified this security group?
  - When was this EC2 instance launched?

Compliance:
  - Prove no unauthorized access to PII
  - Show all privileged operations in audit period
  - Demonstrate MFA enforcement
```

---

### 14.2 AWS VPC Flow Logs Analysis

**Athena Query for VPC Flow Logs**:
```sql
-- Find rejected connections to database port
SELECT
  srcaddr,
  dstaddr,
  srcport,
  dstport,
  action,
  count(*) as connection_count
FROM vpc_flow_logs
WHERE action = 'REJECT'
  AND dstport IN (3306, 5432, 1433, 27017)
  AND start > to_unixtime(now()) - 3600
GROUP BY srcaddr, dstaddr, srcport, dstport, action
ORDER BY connection_count DESC
LIMIT 50;

-- Find data exfiltration candidates (high egress)
SELECT
  srcaddr,
  dstaddr,
  sum(bytes) as total_bytes,
  sum(packets) as total_packets
FROM vpc_flow_logs
WHERE direction = 'egress'
  AND start > to_unixtime(now()) - 86400
GROUP BY srcaddr, dstaddr
HAVING sum(bytes) > 1073741824  -- > 1 GB
ORDER BY total_bytes DESC;
```

---

### 14.3 GCP Cloud Logging

**Log Sink to BigQuery for Analysis**:
```bash
# Create a sink to BigQuery
gcloud logging sinks create prod-logs-bq \
  bigquery.googleapis.com/projects/my-project/datasets/prod_logs \
  --log-filter='resource.type="k8s_container" AND severity>=ERROR'

# Query in BigQuery
SELECT
  timestamp,
  resource.labels.namespace_name,
  resource.labels.container_name,
  jsonPayload.message,
  severity
FROM `my-project.prod_logs.k8s_container_*`
WHERE severity = 'ERROR'
  AND _TABLE_SUFFIX BETWEEN '20260620' AND '20260625'
ORDER BY timestamp DESC
LIMIT 100
```

**GCP Log-Based Metrics**:
```yaml
# Create metric from log pattern
name: custom.googleapis.com/log_based/error_count
description: Count of ERROR log entries
filter: 'resource.type="k8s_container" AND severity="ERROR"'
metric_descriptor:
  metric_kind: DELTA
  value_type: INT64
  labels:
    - key: service
      value_type: STRING
      description: Service name
```

---

### 14.4 Azure Monitor Logs (Log Analytics)

**KQL (Kusto Query Language)**:
```kql
// Find all errors in last hour
AzureDiagnostics
| where TimeGenerated >= ago(1h)
| where Level == "Error"
| project TimeGenerated, Resource, Category, OperationName, ResultDescription
| order by TimeGenerated desc

// Failed login attempts
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType != "0"
| summarize
    FailureCount = count(),
    DistinctIPs = dcount(IPAddress)
    by UserPrincipalName, ResultDescription
| where FailureCount > 5
| order by FailureCount desc

// Kubernetes pod restarts
KubePodInventory
| where TimeGenerated >= ago(1h)
| where RestartCount > 3
| project TimeGenerated, Name, Namespace, ContainerName, RestartCount
| order by RestartCount desc

// Resource usage over time
Perf
| where TimeGenerated >= ago(1h)
| where ObjectName == "Processor" and CounterName == "% Processor Time"
| summarize avg(CounterValue) by Computer, bin(TimeGenerated, 5m)
| render timechart
```

---

## 15. Security & Audit Logging

---

### 15.1 OWASP Logging Requirements

**What to log for security**:
```
Authentication Events:
  ✅ Successful login (with IP, timestamp, method)
  ✅ Failed login attempts (IP, username attempted)
  ✅ Account lockouts
  ✅ Password changes
  ✅ MFA events (setup, removal, bypass)
  ✅ Session creation and termination
  ✅ Privilege escalation (sudo, role assumption)

Authorization Events:
  ✅ Access control failures
  ✅ Unauthorized resource access attempts
  ✅ Changes to permissions/roles

Data Access:
  ✅ Access to sensitive data (PII, financial, health)
  ✅ Bulk data exports
  ✅ Data deletion events

System Events:
  ✅ System and service start/stop
  ✅ Configuration changes
  ✅ Software installation/removal
  ✅ Certificate changes
  ✅ Firewall rule changes
```

---

### 15.2 SIEM Integration

**Common SIEM Use Cases**:
```
Use Case 1: Brute Force Detection
  Rule: > 5 failed logins from same IP in 60 seconds
  Action: Block IP, alert SOC team

Use Case 2: Privilege Escalation
  Rule: User assumes admin role outside business hours
  Action: Alert SOC, require additional verification

Use Case 3: Data Exfiltration
  Rule: User downloads > 100MB of data in 1 hour
  Action: Alert, auto-revoke session

Use Case 4: Lateral Movement
  Rule: Authentication from new IP not seen in 30 days
  Action: Require MFA re-authentication, alert

Use Case 5: Impossible Travel
  Rule: Login from NY, then from London, within 2 hours
  Action: Auto-block, require password reset, alert

Use Case 6: After-Hours Access to Production
  Rule: Production DB access between 11pm-6am local time
  Action: Alert, log full session, auto-expire session in 30min
```

---

### 15.3 Log Integrity

**Ensuring logs cannot be tampered with**:

```bash
# 1. Write-once log storage (append-only)
# AWS CloudTrail: S3 with Object Lock
aws s3api put-object-lock-configuration \
  --bucket my-audit-logs \
  --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Years":7}}}'

# 2. Log signing (verify logs haven't been modified)
# CloudTrail log file validation
aws cloudtrail validate-logs \
  --trail-arn arn:aws:cloudtrail:us-east-1:123456789012:trail/mytrail \
  --start-time 2026-06-25T00:00:00Z \
  --end-time 2026-06-25T01:00:00Z

# 3. Hash chaining (each log entry includes hash of previous)
import hashlib, json

class ChainedLogger:
    def __init__(self):
        self.prev_hash = "0" * 64  # Genesis hash
    
    def log(self, event):
        entry = {
            **event,
            "prev_hash": self.prev_hash,
            "timestamp": datetime.utcnow().isoformat()
        }
        entry_bytes = json.dumps(entry, sort_keys=True).encode()
        entry["hash"] = hashlib.sha256(entry_bytes).hexdigest()
        self.prev_hash = entry["hash"]
        return entry
```

---

## 16. Log Retention & Compliance

---

### 16.1 Retention Requirements by Regulation

| Regulation | Scope | Log Retention Required |
|---|---|---|
| **GDPR** (EU) | Personal data processing | Varies; access logs: typically 1-3 years |
| **HIPAA** (US Healthcare) | Health records | 6 years minimum |
| **PCI DSS** (Payment Card) | Card data environments | 1 year (3 months immediately accessible) |
| **SOC 2** | Service organizations | 1 year minimum |
| **ISO 27001** | Information security | Organization-defined (typically 1-3 years) |
| **NIST 800-53** | US Federal systems | 3+ years |
| **FedRAMP** | Cloud for US Gov | 3 years |
| **CCPA** (California) | Consumer data | Varies by purpose |
| **Financial regulations (SEC, FINRA)** | Financial services | 3-7 years depending on record type |

---

### 16.2 Log Tiering Strategy

```
HOT (0–7 days):     Full-text indexed, instant query
  Cost: $$$
  Storage: Elasticsearch / Loki / Datadog
  Use: Active debugging, real-time alerting

WARM (7–30 days):   Compressed, searchable with delay
  Cost: $$
  Storage: Elasticsearch frozen, Loki, S3 with Athena
  Use: Incident investigation, trend analysis

COLD (30–90 days):  Compressed chunks, slow query
  Cost: $
  Storage: S3 Intelligent-Tiering, GCS Nearline
  Use: Compliance queries, historical analysis

ARCHIVE (90+ days): Glacier/tape, very slow retrieval
  Cost: $0.01/GB/month
  Storage: S3 Glacier, Azure Archive
  Use: Legal hold, regulatory compliance proof
```

**AWS S3 Lifecycle Policy for Logs**:
```json
{
  "Rules": [
    {
      "ID": "LogsLifecycle",
      "Status": "Enabled",
      "Filter": { "Prefix": "logs/" },
      "Transitions": [
        {
          "Days": 30,
          "StorageClass": "STANDARD_IA"
        },
        {
          "Days": 90,
          "StorageClass": "GLACIER"
        },
        {
          "Days": 365,
          "StorageClass": "DEEP_ARCHIVE"
        }
      ],
      "Expiration": {
        "Days": 2555
      }
    }
  ]
}
```

---

## 17. Log Cost Optimization

---

### 17.1 Cost Reduction Strategies

**1. Filter Before Shipping**:
```
Without filtering:  100 GB/day → $X cost
After filtering health checks + debug logs: 40 GB/day → 60% cost reduction

Fluent Bit filter:
[FILTER]
    Name    grep
    Match   *
    Exclude log (?i)(health|ping|metrics|favicon)
    Exclude log GET /health HTTP
```

**2. Sampling High-Volume Healthy Logs**:
```
Strategy: 100% ERROR logs + 10% INFO logs + 0% DEBUG logs

Expected volume reduction: 60-80%

Vector sampling config:
[transforms.sample_info]
  type = "sample"
  inputs = ["parse_json"]
  rate = 10  # Keep 1 in 10 INFO logs
  key_field = "level"
  # Only sample INFO, keep 100% of ERROR/WARN
```

**3. Index Only What You Query**:
```
Elasticsearch: Only index fields you filter/aggregate on
  - Index: level, service, trace_id, status_code, duration_ms
  - Store as keyword (not analyzed): trace_id, user_id, service
  - Full-text analyze only: message field
  - NOT indexed: stack traces, raw headers, debug context

Estimated savings: 40-60% storage reduction
```

**4. Compression**:
```
Raw JSON logs:     10 GB/day
Gzip compressed:    2 GB/day  (80% reduction)
Zstd compressed:    1.5 GB/day (85% reduction)

Most log platforms support compression in transit and storage
```

**5. Use the Right Storage Tier**:
```
Datadog Logs:
  Ingested & Indexed: $0.10/GB ingested + $1.70/GB indexed/month
  Log Archives (S3):  $0.023/GB/month  (93% cost reduction!)
  
Strategy: 
  - Rehydrate from archive only when needed
  - Keep 7 days hot, archive everything else
  - Use Online Archives / Flex Logs for infrequent queries
```

---

### 17.2 Log Volume Calculation

```
Daily Log Volume Estimate:

  Services: 20 microservices
  Avg RPS per service: 500 requests/sec
  Avg log entries per request: 3
  Avg log entry size (JSON): 800 bytes
  Operating hours: 24h

  Raw logs/day =
    20 services × 500 RPS × 3 logs × 800 bytes × 86,400 sec
    = 20 × 500 × 3 × 800 × 86,400
    = 2,073,600,000,000 bytes
    = ~2 TB/day (raw)

  After filtering (remove 40%): 1.2 TB/day
  After compression (80%):        240 GB/day
  
  Elasticsearch @ $0.10/GB ingested:  $24/day = $720/month
  Loki @ $0.05/GB:                    $12/day = $360/month
  S3 archive only:                    $5.52/month
```

---

## 18. Distributed Tracing vs Logging

---

### 18.1 Comparison

| Aspect | Logs | Traces |
|---|---|---|
| **Granularity** | Per event | Per request end-to-end |
| **Structure** | Single events | Parent-child span tree |
| **Volume** | High | Medium |
| **Use case** | What happened | Why is this slow / which service failed |
| **Context** | Local to one component | Spans all services |
| **Correlation** | Manual via trace_id | Built-in via span propagation |
| **Storage** | Loki/ES/CloudWatch | Jaeger/Tempo/Zipkin |
| **Cost** | High (volume) | Lower (sampling possible) |

---

### 18.2 Connecting Logs and Traces

**OpenTelemetry: Inject Trace ID into Logs**:
```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
import structlog

def inject_trace_context(logger, method, event_dict):
    """Add OpenTelemetry trace context to all log entries"""
    span = trace.get_current_span()
    if span.is_recording():
        ctx = span.get_span_context()
        event_dict['trace_id'] = format(ctx.trace_id, '032x')
        event_dict['span_id'] = format(ctx.span_id, '016x')
        event_dict['trace_flags'] = format(ctx.trace_flags, '02x')
    return event_dict

structlog.configure(
    processors=[
        inject_trace_context,
        structlog.processors.JSONRenderer()
    ]
)

# Now every log automatically includes trace_id
# And you can jump from logs → traces in Grafana/Datadog/Jaeger
```

**Grafana: Navigate from Log → Trace**:
```yaml
# Grafana datasource config to link Loki logs → Tempo traces
datasources:
  - name: Loki
    type: loki
    url: http://loki:3100
    jsonData:
      derivedFields:
        - matcherRegex: '"trace_id":"([a-f0-9]+)"'
          name: TraceID
          url: '$${__value.raw}'
          datasourceUid: tempo
          urlDisplayLabel: 'View Trace'
```

---

## 19. ELK / EFK Stack Deep Dive

---

### 19.1 ELK Stack Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     ELK STACK                             │
│                                                           │
│  Sources          Collection    Processing    Storage     │
│  ┌──────────┐                                             │
│  │ App Logs │──┐                                          │
│  └──────────┘  │  ┌──────────┐  ┌─────────┐             │
│  ┌──────────┐  ├─►│ Filebeat │─►│Logstash │             │
│  │ Sys Logs │──┘  └──────────┘  │(filter, │             │
│  └──────────┘                   │ parse,  │  ┌─────────┐│
│  ┌──────────┐  ┌──────────┐    │ enrich) │─►│Elastic  ││
│  │ K8s Logs │─►│Fluent Bit│───►└─────────┘  │ search  ││
│  └──────────┘  └──────────┘                 └────┬────┘│
│                                                   │     │
│  ┌──────────┐  ┌──────────┐                       │     │
│  │  Metrics │─►│Metricbeat│──────────────────────►│     │
│  └──────────┘  └──────────┘                       │     │
│                                                   ▼     │
│                                             ┌─────────┐ │
│                                             │ Kibana  │ │
│                                             │(Dashb., │ │
│                                             │ Alerts) │ │
│                                             └─────────┘ │
└──────────────────────────────────────────────────────────┘
```

### 19.2 Elasticsearch Index Strategy

```bash
# Index naming conventions
logs-nginx-production-2026.06.25     # By service + date
logs-app-2026.06.25                  # Generic app logs by date
security-audit-2026.06              # Monthly security logs

# Data streams (recommended for time-series logs)
# Automatically manages rollover, ILM, backing indices
POST _data_stream/logs-nginx-production

# Check index sizes
GET _cat/indices/logs-*?h=index,docs.count,store.size&s=store.size:desc

# Shard sizing formula
# Aim for 10-50 GB per shard
# Formula: (daily_volume_gb × retention_days) / target_shard_size_gb = num_shards
# Example: (100GB × 7days) / 30GB = 23 shards → use 2 shards × 3 primaries per day
```

---

## 20. Grafana Loki Deep Dive

---

### 20.1 Loki Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      LOKI                                │
│                                                          │
│  ┌───────────┐    ┌───────────┐    ┌─────────────────┐  │
│  │  Clients  │───►│ Distributor│───►│    Ingester     │  │
│  │(Fluent Bit│    │(load       │    │ (in-memory WAL, │  │
│  │ Promtail) │    │ balance)   │    │  flush chunks)  │  │
│  └───────────┘    └───────────┘    └────────┬────────┘  │
│                                             │            │
│                                             ▼            │
│                                   ┌──────────────────┐  │
│  ┌───────────┐    ┌───────────┐   │   Object Store   │  │
│  │  Grafana  │◄───│  Querier  │◄──│(S3/GCS/Azure     │  │
│  │(LogQL UI) │    │(search +  │   │ Blob / Filesystem)│  │
│  └───────────┘    │ aggregate)│   └──────────────────┘  │
│                   └───────────┘                          │
│                                   ┌──────────────────┐  │
│                                   │ Index (BoltDB/   │  │
│                                   │  Cassandra/DDB)  │  │
│                                   │ Stores: labels   │  │
│                                   └──────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### 20.2 LogQL Advanced Examples

```logql
# Count log lines by level over time
sum by (level) (
  count_over_time({job="api-service"}[5m])
)

# Error rate as percentage
(
  sum(rate({job="api-service"} |= "ERROR" [5m]))
  /
  sum(rate({job="api-service"} [5m]))
) * 100

# Extract and aggregate latency from logs
# (log line: "request completed in 145ms")
{job="api-service"}
| regexp `completed in (?P<latency>\d+)ms`
| unwrap latency
| quantile_over_time(0.99, [5m]) by (service)

# Find all unique error types
{job="api-service"} | json | level="ERROR"
| line_format "{{.error_type}}"
| distinct_count_over_time([1h])

# Pattern detection (find abnormal log volume)
sum(rate({namespace="production"}[5m])) by (pod)
> 2 * avg_over_time(sum(rate({namespace="production"}[5m])) by (pod)[1h:5m])
```

---

## 21. Quick Reference & Cheat Sheets

---

### Log Level Quick Reference

```
FATAL/CRITICAL  → Service/process is DOWN. Page on-call. Immediate action.
ERROR           → Operation FAILED. Alert team. Investigate within 15 min.
WARN            → Unexpected but handled. Review within 1 hour.
INFO            → Normal operations. Informational only.
DEBUG           → Diagnostic detail. NEVER in production default.
TRACE           → Ultra-verbose. Development ONLY.
```

### Log Format Quick Picks

```
API / Microservices    → JSON structured
System / Infrastructure → Syslog (RFC 5424)
Web Server             → Combined Log Format + upstream fields
Security / SIEM        → CEF (Common Event Format)
Kubernetes Native      → JSON (stdout) + labels
Go Applications        → logfmt (key=value)
```

### Log Shipper Quick Picks

```
Kubernetes clusters    → Fluent Bit DaemonSet
Complex routing needs  → Fluentd
ELK-focused            → Filebeat
Modern pipelines       → Vector
High-throughput edge   → Fluent Bit
```

### Log Storage Quick Picks

```
Rich search + analytics      → Elasticsearch
Cost-effective K8s logs      → Grafana Loki
Enterprise SIEM              → Splunk
AWS-native workloads         → CloudWatch Logs
GCP-native workloads         → Cloud Logging
Azure-native workloads       → Azure Monitor Logs
Long-term archive            → S3 / GCS / Azure Blob
```

### Log Retention Quick Reference

```
PCI DSS:  1 year (3 months immediately accessible)
HIPAA:    6 years
SOC 2:    1 year minimum
GDPR:     Varies — minimize retention (data minimization principle)
ISO 27001: Organization-defined (document and justify)
General:  Hot: 7d | Warm: 30d | Cold: 90d | Archive: 365d+
```

### Essential Log Fields Checklist

```
Every log entry MUST have:
  ✅ timestamp     (ISO 8601 UTC)
  ✅ level         (ERROR, WARN, INFO, DEBUG)
  ✅ service       (service/application name)
  ✅ message       (human-readable description)

Production logs SHOULD have:
  ✅ trace_id      (correlate across services)
  ✅ environment   (production/staging/dev)
  ✅ version       (app version/git SHA)
  ✅ host/pod      (where it ran)

Contextual (include when relevant):
  ✅ user_id       (who triggered it)
  ✅ request_id    (unique per HTTP request)
  ✅ duration_ms   (how long it took)
  ✅ status_code   (HTTP/gRPC status)
  ✅ error details (type, message, stack)
```

### Common LogQL / KQL / SPL Cheat Sheet

```logql
# Loki - Find errors
{job="myapp"} |= "ERROR"

# Loki - Error rate
sum(rate({job="myapp"} |= "ERROR" [5m])) / sum(rate({job="myapp"}[5m]))

# Loki - Parse JSON
{job="myapp"} | json | level="ERROR" | duration > 1000
```

```kql
# Kibana - Find errors
level: ERROR AND service: "api-service"

# Kibana - Slow requests
duration_ms > 1000 AND status_code: 200

# Kibana - Last hour
@timestamp >= now-1h AND level: ERROR
```

```splunk
# Splunk - Error count by service
index=prod level=ERROR | stats count by service | sort -count

# Splunk - Top slow endpoints
index=prod | where duration_ms > 1000 | stats avg(duration_ms), count by uri | sort -avg(duration_ms)
```

```sql
-- CloudWatch Insights - Error analysis
fields @timestamp, service, message
| filter level = "ERROR"
| stats count() as error_count by service
| sort error_count desc
```

---

*Last Updated: June 2026 | Maintained by DevOps / SRE Team*
