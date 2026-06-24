# 📊 DevOps Metrics Reference Guide

> A comprehensive reference for DevOps, SRE, and Platform engineers covering all key metrics — how they're calculated, what they mean, real-world examples, and when to use them.

---

## Table of Contents

1. [DORA Metrics](#1-dora-metrics)
2. [Availability & Reliability Metrics](#2-availability--reliability-metrics)
3. [Performance & Latency Metrics](#3-performance--latency-metrics)
4. [Error & Failure Metrics](#4-error--failure-metrics)
5. [Infrastructure & Resource Metrics](#5-infrastructure--resource-metrics)
6. [Security Metrics](#6-security-metrics)
7. [CI/CD Pipeline Metrics](#7-cicd-pipeline-metrics)
8. [Cost & Efficiency Metrics](#8-cost--efficiency-metrics)
9. [Capacity & Scalability Metrics](#9-capacity--scalability-metrics)
10. [Observability Metrics](#10-observability-metrics)
11. [Quick Reference: Which Metric to Use When](#11-quick-reference-which-metric-to-use-when)
12. [GPU Metrics](#12-gpu-metrics)
13. [Deep CPU Metrics](#13-deep-cpu-metrics)
14. [Application-Specific Metrics](#14-application-specific-metrics)
15. [Docker Metrics](#15-docker-metrics)
16. [Kubernetes Deep-Dive Metrics](#16-kubernetes-deep-dive-metrics)
17. [Cloud Platform Metrics (AWS / GCP / Azure)](#17-cloud-platform-metrics-aws--gcp--azure)

---

## 1. DORA Metrics

> **DORA (DevOps Research and Assessment)** metrics are the gold standard for measuring software delivery performance. Defined by the DORA team at Google, they benchmark engineering teams across four key dimensions.

---

### 1.1 Deployment Frequency (DF)

**Definition**: How often an organization successfully releases software to production.

**Formula**:
```
Deployment Frequency = Total Deployments / Time Period
```

**Benchmark Tiers**:
| Level | Frequency |
|---|---|
| 🔴 Low | Less than once per month |
| 🟡 Medium | Once per month to once per week |
| 🟢 High | Once per week to once per day |
| 🚀 Elite | Multiple times per day |

**Example**:
- Team A deployed 42 times in June (30 days)
- DF = 42 / 30 = **1.4 deployments/day** → Elite performer

**When to use**:
- Measuring team agility and CI/CD maturity
- Setting OKRs for engineering velocity
- Comparing deployment cadence across teams

---

### 1.2 Lead Time for Changes (LTC)

**Definition**: The time it takes for a code commit to reach production.

**Formula**:
```
Lead Time = Time of Production Deploy − Time of First Commit
```

**Benchmark Tiers**:
| Level | Lead Time |
|---|---|
| 🔴 Low | > 6 months |
| 🟡 Medium | 1 week – 1 month |
| 🟢 High | 1 day – 1 week |
| 🚀 Elite | < 1 hour |

**Example**:
```
Commit at:    Monday 09:00
Deploy at:    Monday 11:30
Lead Time  =  2 hours 30 minutes → Elite
```

**When to use**:
- Identifying bottlenecks in the delivery pipeline
- Evaluating the impact of automation improvements
- Tracking developer experience improvements

---

### 1.3 Change Failure Rate (CFR)

**Definition**: The percentage of deployments that cause a production failure requiring hotfix, rollback, or incident.

**Formula**:
```
CFR (%) = (Failed Deployments / Total Deployments) × 100
```

**Benchmark Tiers**:
| Level | CFR |
|---|---|
| 🔴 Low | 46–60% |
| 🟡 Medium | 16–45% |
| 🟢 High | 0–15% |
| 🚀 Elite | 0–15% (with strong recovery) |

**Example**:
```
Total Deployments:  80
Failed Deployments: 6
CFR = (6 / 80) × 100 = 7.5% → High performer
```

**What counts as a failure?**
- Rollback triggered after deploy
- Hotfix pushed within 1 hour of deploy
- P1/P2 incident directly caused by the release

**When to use**:
- Assessing release quality and testing rigor
- Investigating flaky CI pipelines
- Setting quality gates in CD pipelines

---

### 1.4 Mean Time to Recovery (MTTR)

**Definition**: The average time it takes to restore service after a production failure or incident.

**Formula**:
```
MTTR = Total Downtime / Number of Incidents
```

**Benchmark Tiers**:
| Level | MTTR |
|---|---|
| 🔴 Low | > 1 month |
| 🟡 Medium | 1 week – 1 month |
| 🟢 High | < 1 day |
| 🚀 Elite | < 1 hour |

**Example**:
```
Incident 1 downtime: 45 min
Incident 2 downtime: 20 min
Incident 3 downtime: 35 min

MTTR = (45 + 20 + 35) / 3 = 33.3 minutes → Elite
```

**When to use**:
- Measuring incident response effectiveness
- Evaluating on-call runbooks and playbooks
- Post-mortem analysis and SRE benchmarking

---

## 2. Availability & Reliability Metrics

---

### 2.1 Uptime / Availability

**Definition**: The percentage of time a system is operational and accessible to users.

**Formula**:
```
Availability (%) = (Uptime / Total Time) × 100
                 = ((Total Time − Downtime) / Total Time) × 100
```

**SLA Nines Table**:
| Availability | Downtime/Year | Downtime/Month | Downtime/Week |
|---|---|---|---|
| 99% (two 9s) | 3.65 days | 7.2 hours | 1.68 hours |
| 99.9% (three 9s) | 8.76 hours | 43.8 min | 10.1 min |
| 99.99% (four 9s) | 52.6 min | 4.38 min | 1.01 min |
| 99.999% (five 9s) | 5.26 min | 26.3 sec | 6.05 sec |

**Example**:
```
Total hours in month:  720
Downtime this month:   2.5 hours

Availability = ((720 − 2.5) / 720) × 100 = 99.653%
```

**When to use**:
- Defining SLAs with customers
- Monitoring infrastructure health dashboards
- Setting SLOs for services

---

### 2.2 Service Level Indicators (SLIs)

**Definition**: A quantitative measure of a specific aspect of a service's behavior. SLIs are the raw metrics that feed into SLOs.

**Common SLI Types**:
| SLI Type | What it Measures | Example |
|---|---|---|
| Availability SLI | Request success rate | 99.8% of requests returned HTTP 2xx |
| Latency SLI | Response time | 95% of requests < 200ms |
| Throughput SLI | Requests served | 10,000 req/sec sustained |
| Error Rate SLI | Fraction of bad requests | < 0.1% HTTP 5xx responses |
| Durability SLI | Data intact probability | 99.9999% data intact |

**Formula (Availability SLI)**:
```
Availability SLI = (Good Requests / Total Requests) × 100
```

**Example**:
```
Total requests last hour:  1,000,000
Failed (5xx) requests:     1,200

Availability SLI = ((1,000,000 − 1,200) / 1,000,000) × 100 = 99.88%
```

**When to use**:
- As inputs to SLO calculations
- In alerting rules (alert when SLI drops below SLO)
- When defining what "good" behavior means for a service

---

### 2.3 Service Level Objectives (SLOs)

**Definition**: A target value or range for an SLI that defines acceptable service performance.

**Structure**:
```
SLO = SLI metric + Target threshold + Time window

Example: "99.9% of requests will return < 300ms over a 30-day rolling window"
```

**Error Budget Calculation**:
```
Error Budget = 100% − SLO target

If SLO = 99.9%:
Error Budget = 0.1% of requests may fail

In a month with 10M requests:
Allowed failures = 10,000,000 × 0.001 = 10,000 requests
```

**When to use**:
- Defining acceptable reliability targets
- Deciding when to freeze feature work to fix reliability
- Framing conversations between engineering and product

---

### 2.4 Error Budget

**Definition**: The allowable amount of unreliability within a given time window, derived from the SLO.

**Formula**:
```
Error Budget Remaining (%) = 
  (Actual Reliability − SLO) / (100% − SLO) × 100

Error Budget Consumed (%) = 
  (Failed Requests / Total Allowed Failures) × 100
```

**Example**:
```
SLO target:           99.9%
Actual reliability:   99.75%

Budget consumed = (99.9% − 99.75%) / (100% − 99.9%)
               = 0.15% / 0.1% = 150% → Budget exceeded!
```

**When to use**:
- Deciding whether to ship new features vs. fix reliability
- Setting freeze periods for deployments
- Driving SRE prioritization discussions

---

## 3. Performance & Latency Metrics

---

### 3.1 Response Time / Latency

**Definition**: The time taken for a system to respond to a request from the moment it is sent.

**Types**:
```
Network Latency   = Time data takes to travel across network
Processing Time   = Time server takes to compute response
Total Round-Trip  = Network Latency × 2 + Processing Time
```

**Percentile Measurements (preferred over averages)**:
| Percentile | Meaning |
|---|---|
| p50 (median) | 50% of requests are faster than this |
| p90 | 90% of requests are faster than this |
| p95 | 95% of requests are faster than this |
| p99 | 99% of requests are faster than this ("tail latency") |
| p99.9 | 99.9% of requests are faster than this |

**Why percentiles > averages**:
```
10 request times (ms): [12, 15, 14, 13, 16, 11, 14, 200, 13, 12]

Average   = 32ms  ← distorted by the outlier (200ms)
p95       = 16ms  ← more representative of typical experience
p99       = 200ms ← catches the tail problem
```

**When to use**:
- p50/p90 for general user experience benchmarking
- p99/p99.9 for SLO definitions in critical paths
- Comparing performance before/after optimization

---

### 3.2 Throughput

**Definition**: The number of requests, transactions, or operations a system processes per unit of time.

**Formula**:
```
Throughput = Total Requests (or Transactions) / Time Period
```

**Units**: req/sec (RPS), transactions/sec (TPS), messages/sec

**Example**:
```
API received 540,000 requests in 1 minute
Throughput = 540,000 / 60 = 9,000 RPS
```

**Throughput vs. Latency Tradeoff**:
```
High throughput + low latency = ideal (rare)
High throughput + high latency = system under stress
Low throughput + low latency  = underutilized or quiet
```

**When to use**:
- Load testing baseline definition
- Capacity planning and auto-scaling policies
- Identifying if a queue/service is keeping up with demand

---

### 3.3 Time to First Byte (TTFB)

**Definition**: The time between making an HTTP request and receiving the first byte of the response.

**Formula**:
```
TTFB = DNS Lookup Time + TCP Connect Time + TLS Handshake + Server Processing Time
```

**Good TTFB Targets**:
| Score | TTFB |
|---|---|
| ✅ Good | < 800ms |
| ⚠️ Needs Improvement | 800ms – 1800ms |
| ❌ Poor | > 1800ms |

**Example**:
```
DNS:        20ms
TCP:        35ms
TLS:        60ms
Processing: 185ms

TTFB = 20 + 35 + 60 + 185 = 300ms ✅
```

**When to use**:
- Web performance audits (Core Web Vitals)
- Diagnosing server-side slowness vs. network slowness
- CDN effectiveness evaluation

---

### 3.4 Apdex Score (Application Performance Index)

**Definition**: A standardized way to measure user satisfaction with application response time.

**Formula**:
```
Apdex = (Satisfied + (Tolerating / 2)) / Total Requests

Where (given a threshold T):
  Satisfied  = requests completed in ≤ T seconds
  Tolerating = requests completed in T – 4T seconds
  Frustrated = requests taking > 4T seconds
```

**Score Interpretation**:
| Apdex Score | User Satisfaction |
|---|---|
| 1.0 | Perfect |
| 0.94 – 1.0 | Excellent |
| 0.85 – 0.94 | Good |
| 0.70 – 0.85 | Fair |
| 0.50 – 0.70 | Poor |
| < 0.50 | Unacceptable |

**Example** (T = 500ms):
```
1000 total requests:
  Satisfied  (≤ 500ms):    750
  Tolerating (500ms–2s):   180
  Frustrated (> 2s):        70

Apdex = (750 + (180/2)) / 1000
      = (750 + 90) / 1000 = 0.84 → Fair
```

**When to use**:
- Single performance score for stakeholder reporting
- Alerting when user experience degrades
- Comparing application versions after deploy

---

## 4. Error & Failure Metrics

---

### 4.1 Error Rate

**Definition**: The percentage of requests that result in an error.

**Formula**:
```
Error Rate (%) = (Error Responses / Total Requests) × 100
```

**HTTP Status Classification**:
| Status Range | Type | Count as Error? |
|---|---|---|
| 2xx | Success | No |
| 3xx | Redirect | No |
| 4xx | Client Error | Sometimes (depends on context) |
| 5xx | Server Error | Yes — always |

**Example**:
```
Total requests in 1 hour: 500,000
5xx errors:                1,250
4xx errors (unintended):     500

Error Rate (5xx only) = (1,250 / 500,000) × 100 = 0.25%
```

**When to use**:
- Real-time alerting thresholds (e.g., alert if error rate > 1%)
- Post-deploy health checks
- SLI measurement input

---

### 4.2 Mean Time Between Failures (MTBF)

**Definition**: The average time a system operates between failures (for repairable systems).

**Formula**:
```
MTBF = Total Operational Time / Number of Failures
```

**Example**:
```
System ran for 720 hours in a month
Experienced 3 failures

MTBF = 720 / 3 = 240 hours between failures
```

**MTBF vs. MTTR**:
```
High MTBF + Low MTTR = Reliable and recoverable (ideal)
Low MTBF  + High MTTR = Fragile and slow to recover (danger zone)
```

**When to use**:
- Hardware reliability analysis
- Predicting failure frequency for capacity planning
- Evaluating system stability improvements

---

### 4.3 Mean Time to Detect (MTTD)

**Definition**: The average time between when a failure occurs and when it is detected/alerted.

**Formula**:
```
MTTD = Time of Detection − Time of Failure Occurrence
       (averaged over multiple incidents)
```

**Example**:
```
Incident 1: Failure at 14:00, Alert fired at 14:08 → 8 min
Incident 2: Failure at 09:00, Alert fired at 09:03 → 3 min
Incident 3: Failure at 22:00, Alert fired at 22:12 → 12 min

MTTD = (8 + 3 + 12) / 3 = 7.67 minutes
```

**When to use**:
- Evaluating alerting and monitoring effectiveness
- Improving observability stack
- SRE on-call response readiness

---

### 4.4 Mean Time to Resolve (MTTR — Resolution)

**Definition**: Similar to MTTR but specifically tracks the total time from detection to full resolution (including root cause fix, not just service restore).

**Formula**:
```
MTTR (Resolve) = Time of Full Resolution − Time of Detection
```

**MTTR Variants Summary**:
| Variant | Measures |
|---|---|
| MTTD | Detection speed |
| MTTR (Restore) | How fast service is back up |
| MTTR (Resolve) | How fast root cause is fixed |
| MTTF (Mean Time to Failure) | How long until next failure |

---

## 5. Infrastructure & Resource Metrics

---

### 5.1 CPU Utilization

**Definition**: The percentage of CPU capacity being used.

**Formula**:
```
CPU Utilization (%) = (CPU Time Used / Total CPU Time Available) × 100
```

**Thresholds**:
| Range | Status | Action |
|---|---|---|
| 0–50% | ✅ Healthy | Normal operations |
| 50–70% | 🟡 Monitor | Watch for spikes |
| 70–85% | ⚠️ Warning | Investigate, consider scaling |
| 85%+ | 🔴 Critical | Scale immediately, risk of throttling |

**Example**:
```
4-core server, each core at:  core1=80%, core2=70%, core3=90%, core4=60%
Average CPU = (80+70+90+60)/4 = 75% → Warning threshold
```

**When to use**:
- Auto-scaling trigger conditions
- Rightsizing cloud instances
- Identifying CPU-bound bottlenecks

---

### 5.2 Memory Utilization

**Definition**: Percentage of total available RAM currently in use.

**Formula**:
```
Memory Utilization (%) = (Used Memory / Total Memory) × 100

Used Memory = Total − Free − Buffers − Cache  (Linux)
```

**Example**:
```
Total RAM:     16 GB
Used:           9 GB
Buffers/Cache:  3 GB
Truly free:     4 GB

Effective Utilization = (9 / 16) × 100 = 56.25% → Healthy
```

**Memory Leak Detection**:
```
Healthy:      Memory stays stable over time
Leak Pattern: Memory grows continuously and never releases
```

**When to use**:
- Detecting memory leaks in long-running services
- Kubernetes Pod memory limit tuning
- Auto-scaling triggers (alongside CPU)

---

### 5.3 Disk I/O

**Definition**: Measures the rate of read and write operations to storage devices.

**Key Metrics**:
| Metric | Formula | Unit |
|---|---|---|
| Read Throughput | Bytes read / second | MB/s |
| Write Throughput | Bytes written / second | MB/s |
| IOPS (Read) | Read operations / second | ops/sec |
| IOPS (Write) | Write operations / second | ops/sec |
| I/O Wait | % CPU time waiting for I/O | % |
| I/O Latency | Avg time per I/O operation | ms |

**Example**:
```
In 1 second:
  Read: 4,500 operations, 45 MB
  Write: 2,000 operations, 20 MB

Read IOPS  = 4,500
Write IOPS = 2,000
Read BW    = 45 MB/s
Write BW   = 20 MB/s
```

**When to use**:
- Database performance tuning
- Identifying disk-bound applications
- Storage tier selection (SSD vs HDD vs NVMe)

---

### 5.4 Network Bandwidth Utilization

**Definition**: The proportion of available network capacity that is currently being used.

**Formula**:
```
Bandwidth Utilization (%) = (Current Traffic / Max Capacity) × 100
```

**Key Metrics to Track**:
- **Ingress** (bytes in per second)
- **Egress** (bytes out per second)
- **Packet Loss** (%)
- **Retransmission Rate** (%)

**Example**:
```
Network link capacity:  1 Gbps = 125 MB/s
Current egress:         87 MB/s

Utilization = (87 / 125) × 100 = 69.6% → Approaching warning threshold
```

**When to use**:
- CDN and load balancer sizing
- Identifying noisy neighbors in multi-tenant systems
- Egress cost optimization in cloud environments

---

### 5.5 Saturation

**Definition**: How much "extra work" a system has that it cannot yet serve — the degree to which resources are overloaded.

**Examples of saturation signals**:
```
CPU:     Run queue length > number of CPU cores
Memory:  Swap usage growing
Disk:    I/O queue depth increasing
Network: TX/RX drops, retransmissions increasing
```

**USE Method** (Utilization, Saturation, Errors):
```
For every resource, measure:
  U = Utilization  → How busy is the resource?
  S = Saturation   → How much extra work is queued?
  E = Errors        → Are errors occurring?
```

**When to use**:
- Systematic performance troubleshooting
- Pre-emptive capacity planning
- Identifying which resource is the bottleneck

---

## 6. Security Metrics

---

### 6.1 Mean Time to Detect a Threat (MTTD — Security)

**Definition**: The average time from when a security incident begins until it is detected by the security team or tooling.

**Formula**:
```
MTTD = Sum(Detection Time − Incident Start Time) / Number of Incidents
```

**Industry Average**: ~197 days (IBM Cost of Data Breach Report 2023)
**Target for mature orgs**: < 1 hour for critical threats

**Example**:
```
Breach started:   Jan 5, 00:00
Detected:         Jan 5, 04:30
MTTD:             4.5 hours
```

**When to use**:
- Evaluating SIEM and threat detection effectiveness
- Security KPI dashboards
- Justifying security tooling investment

---

### 6.2 Mean Time to Contain (MTTC)

**Definition**: Average time from detection to successfully containing the threat (isolating affected systems).

**Formula**:
```
MTTC = Time of Containment − Time of Detection
```

**Example**:
```
Threat detected at: 14:00
Systems isolated at: 14:45
MTTC = 45 minutes
```

**When to use**:
- Measuring incident response playbook efficiency
- SOC team performance evaluation

---

### 6.3 Vulnerability Count by Severity

**Definition**: Number of known vulnerabilities broken down by CVSS severity level.

**CVSS Severity Bands**:
| Score | Severity | Response SLA |
|---|---|---|
| 9.0–10.0 | 🔴 Critical | Patch within 24 hours |
| 7.0–8.9 | 🟠 High | Patch within 7 days |
| 4.0–6.9 | 🟡 Medium | Patch within 30 days |
| 0.1–3.9 | 🟢 Low | Patch within 90 days |
| 0.0 | ⚪ None | Informational |

**Formula**:
```
Vulnerability Density = Number of Vulns / Lines of Code (or per service/component)
```

**Example**:
```
Weekly scan results:
  Critical: 2
  High:     8
  Medium:  34
  Low:     91

Risk Score = (2×10) + (8×7) + (34×4) + (91×1) = 20+56+136+91 = 303
```

**When to use**:
- Prioritizing security remediation work
- Tracking security posture over time
- Compliance reporting (SOC2, ISO 27001)

---

### 6.4 Patch Compliance Rate

**Definition**: The percentage of systems or packages that have required security patches applied within the required SLA.

**Formula**:
```
Patch Compliance Rate (%) = (Patched Systems / Total Systems) × 100
```

**Example**:
```
Total servers:   200
Patched on time: 182

Compliance Rate = (182 / 200) × 100 = 91%
```

**When to use**:
- Security compliance audits
- Tracking vulnerability remediation velocity
- CI/CD security gates

---

### 6.5 Failed Login Attempts / Authentication Failure Rate

**Definition**: The rate of failed authentication attempts, used to detect brute force attacks.

**Formula**:
```
Auth Failure Rate = Failed Logins / Total Login Attempts × 100
```

**Baseline vs. Anomaly Detection**:
```
Normal baseline:    2–5% failure rate
Brute force signal: > 50% failure rate in burst window
Account takeover:   High success rate after burst of failures
```

**When to use**:
- WAF and IDS rule tuning
- Security alerting for identity systems
- Anomaly detection in authentication services

---

## 7. CI/CD Pipeline Metrics

---

### 7.1 Pipeline Success Rate

**Definition**: Percentage of CI/CD pipeline runs that complete successfully.

**Formula**:
```
Pipeline Success Rate (%) = (Successful Runs / Total Runs) × 100
```

**Example**:
```
Total pipeline runs this week: 340
Successful runs:               306
Failed runs:                    34

Success Rate = (306 / 340) × 100 = 90%
```

**When to use**:
- Monitoring CI/CD health
- Identifying flaky tests or unstable builds
- Setting quality gates for deployments

---

### 7.2 Pipeline Duration (Build Time)

**Definition**: The total time from pipeline trigger to completion.

**Breakdown**:
```
Total Pipeline Duration = 
  Checkout Time
  + Dependency Install Time
  + Build/Compile Time
  + Unit Test Time
  + Integration Test Time
  + Security Scan Time
  + Deploy Time
```

**Targets**:
| Stage | Target |
|---|---|
| Full CI pipeline | < 10 minutes |
| Unit tests only | < 2 minutes |
| Full CD pipeline | < 20 minutes |

**Example**:
```
Pipeline stages:
  Checkout:      15s
  Install deps:  90s
  Build:        120s
  Tests:        180s
  Security:      60s
  Deploy:        45s
  
Total = 510s = 8.5 minutes ✅
```

**When to use**:
- Developer experience optimization
- Finding slow stages for parallelization
- Tracking impact of pipeline improvements

---

### 7.3 Test Coverage

**Definition**: The percentage of code that is exercised by automated tests.

**Types**:
| Type | What It Measures |
|---|---|
| Line Coverage | % of code lines executed |
| Branch Coverage | % of conditional branches taken |
| Statement Coverage | % of statements executed |
| Function Coverage | % of functions called |

**Formula**:
```
Coverage (%) = (Lines Covered by Tests / Total Lines) × 100
```

**Recommended Minimums**:
| Layer | Minimum Coverage |
|---|---|
| Unit Tests | 80% |
| Critical Paths | 95%+ |
| Integration | 60%+ |

**Example**:
```
Total code lines:         2,500
Lines covered by tests:   2,100

Coverage = (2,100 / 2,500) × 100 = 84% ✅
```

**When to use**:
- Enforcing quality gates in CI
- Identifying under-tested modules
- Code review guidelines

---

### 7.4 Flaky Test Rate

**Definition**: The percentage of tests that produce inconsistent results (pass/fail) without code changes.

**Formula**:
```
Flaky Test Rate (%) = (Tests with Inconsistent Results / Total Tests) × 100
```

**Example**:
```
Total tests:    1,200
Flaky tests:       24

Flaky Rate = (24 / 1,200) × 100 = 2% → Target is < 1%
```

**When to use**:
- Identifying tests that need quarantining
- Measuring CI/CD reliability
- Improving developer trust in the test suite

---

## 8. Cost & Efficiency Metrics

---

### 8.1 Cloud Cost per Request

**Definition**: The average cloud infrastructure cost to serve one request.

**Formula**:
```
Cost per Request = Total Infrastructure Cost / Total Requests Served
```

**Example**:
```
Monthly cloud bill: $12,000
Monthly requests:   480,000,000

Cost per Request = $12,000 / 480,000,000 = $0.000025 per request
```

**When to use**:
- FinOps and cloud cost optimization
- Unit economics calculation for pricing
- Comparing architectural choices by cost efficiency

---

### 8.2 Infrastructure Cost per User (CPPU)

**Definition**: Cost of infrastructure per paying or active user per time period.

**Formula**:
```
CPPU = Total Infrastructure Cost / Number of Active Users
```

**Example**:
```
Monthly infra cost: $45,000
Monthly active users: 15,000

CPPU = $45,000 / 15,000 = $3.00 per user/month
```

**When to use**:
- SaaS unit economics benchmarking
- Evaluating cost-efficiency of scaling
- Investor reporting and business planning

---

### 8.3 Resource Utilization Efficiency

**Definition**: How effectively provisioned resources are being used vs. wasted.

**Formula**:
```
Utilization Efficiency (%) = (Actual Usage / Provisioned Capacity) × 100
```

**Example**:
```
Provisioned: 100 vCPUs
Actual avg usage: 34 vCPUs

Efficiency = (34 / 100) × 100 = 34% → Likely over-provisioned
```

**When to use**:
- Cloud rightsizing analysis
- Reserved instance purchase decisions
- Kubernetes resource quota tuning

---

## 9. Capacity & Scalability Metrics

---

### 9.1 Requests per Second at Saturation

**Definition**: The maximum RPS a system can handle before performance degrades significantly.

**Measured via**: Load tests (e.g., k6, Locust, JMeter)

**Formula**:
```
Saturation Point = RPS at which p99 latency exceeds SLO threshold
                   OR error rate exceeds acceptable limit
```

**Example**:
```
Load test results:
  @ 1,000 RPS: p99=120ms, errors=0.0%
  @ 5,000 RPS: p99=190ms, errors=0.1%
  @ 8,000 RPS: p99=450ms, errors=0.5%   ← Approaching saturation
  @ 10,000 RPS: p99=2,100ms, errors=5%  ← Saturated

Saturation Point ≈ 8,000–9,000 RPS
```

**When to use**:
- Capacity planning and auto-scaling thresholds
- Determining when to scale horizontally
- Pre-launch load testing

---

### 9.2 Scale-Out Efficiency

**Definition**: How well a system maintains performance as instances are added.

**Formula**:
```
Ideal:    2x instances = 2x capacity (linear scaling)
Actual efficiency = (Actual capacity gain / Expected capacity gain) × 100
```

**Example**:
```
1 instance: 1,000 RPS
2 instances: 1,850 RPS (expected 2,000)

Scale-Out Efficiency = (1,850 / 2,000) × 100 = 92.5%
```

**When to use**:
- Evaluating stateless vs stateful service design
- Auto-scaling policy optimization
- Microservices vs. monolith scaling comparison

---

### 9.3 Queue Depth / Backlog

**Definition**: The number of messages or tasks waiting to be processed in a queue.

**Formula**:
```
Backlog Growth Rate = Enqueue Rate − Dequeue Rate

If Backlog Growth Rate > 0: Queue is growing (consumer falling behind)
If Backlog Growth Rate < 0: Queue is draining (consumer catching up)
If Backlog Growth Rate = 0: Stable processing
```

**Example**:
```
Messages enqueued per sec:  500
Messages processed per sec: 420

Backlog Growth = 500 − 420 = +80 msg/sec → Growing, scale consumers!
```

**When to use**:
- Kafka/RabbitMQ/SQS consumer lag monitoring
- Auto-scaling consumers based on queue depth
- Identifying processing bottlenecks in event-driven systems

---

## 10. Observability Metrics

---

### 10.1 The Four Golden Signals (Google SRE)

> Defined in the Google SRE Handbook as the minimum set of metrics to monitor for any user-facing service.

| Signal | Description | Example Metric |
|---|---|---|
| **Latency** | Time to serve requests (separate success vs error) | p99 response time |
| **Traffic** | Demand on the system | Requests per second |
| **Errors** | Rate of failed requests | HTTP 5xx rate |
| **Saturation** | How full the service is | CPU %, queue depth |

```
Mnemonic: LETS (Latency, Errors, Traffic, Saturation)
```

**When to use**:
- Designing monitoring dashboards from scratch
- Defining minimum viable alerting for any service
- On-call runbook development

---

### 10.2 RED Method

> Designed for **request-driven services** (microservices, APIs).

| Signal | Metric |
|---|---|
| **R**ate | Requests per second |
| **E**rrors | Number of failed requests per second |
| **D**uration | Distribution of request durations (latency) |

**When to use**:
- Microservices and API monitoring
- Service mesh observability (Istio, Linkerd)
- Kubernetes service monitoring

---

### 10.3 USE Method

> Designed for **infrastructure and resource monitoring**.

| Signal | Metric |
|---|---|
| **U**tilization | % time resource is busy |
| **S**aturation | Queue length or extra work pending |
| **E**rrors | Error events (disk errors, network drops) |

**When to use**:
- Node and infrastructure-level monitoring
- Diagnosing hardware/OS-level bottlenecks
- Kubernetes node monitoring

---

### 10.4 Log Volume & Log Error Rate

**Definition**: Volume of log entries and fraction that are error-level.

**Formula**:
```
Log Error Rate (%) = (ERROR + FATAL log lines / Total log lines) × 100
```

**Example**:
```
Total logs per minute: 50,000
ERROR-level logs:       1,200
FATAL-level logs:          15

Log Error Rate = (1,215 / 50,000) × 100 = 2.43%
```

**When to use**:
- Log-based alerting (Loki, CloudWatch, Datadog)
- Cost management for log ingestion
- Debugging and root cause analysis

---

### 10.5 Trace Sampling Rate & Span Error Rate

**Definition**: In distributed tracing, the fraction of requests traced and the fraction of spans with errors.

**Formula**:
```
Span Error Rate = (Error Spans / Total Spans) × 100
```

**Example**:
```
10,000 spans from payment-service in 5 min
320 spans had errors

Span Error Rate = (320 / 10,000) × 100 = 3.2%
```

**When to use**:
- Distributed system debugging (Jaeger, Tempo, Zipkin)
- Identifying which microservice causes latency
- Root cause analysis across service boundaries

---

## 11. Quick Reference: Which Metric to Use When

---

### By Scenario

| Scenario | Primary Metrics | Secondary Metrics |
|---|---|---|
| 📦 **New deployment health check** | Error Rate, p99 Latency, Deployment Frequency | Apdex, MTTR |
| 🔥 **Active incident / outage** | Error Rate, Availability, MTTD, MTTR | Saturation, CPU/Memory |
| 🏗️ **Capacity planning** | Throughput, CPU/Memory Utilization, Queue Depth | Scale-Out Efficiency, Cost per Request |
| 🔒 **Security audit** | MTTD (security), Vuln Count by Severity, Patch Compliance | Auth Failure Rate, MTTC |
| 💰 **Cloud cost review** | Cost per Request, CPPU, Resource Utilization Efficiency | Throughput, Idle capacity |
| 🧪 **CI/CD pipeline health** | Pipeline Success Rate, Pipeline Duration, Test Coverage | Flaky Test Rate, Lead Time |
| 📈 **Executive/leadership reporting** | DORA Metrics (all 4), Availability, MTTR | Error Budget, CFR |
| 🔍 **Performance debugging** | p50/p95/p99 Latency, Throughput, Apdex | CPU/Disk I/O, TTFB |
| 🗂️ **On-call / SRE triage** | Four Golden Signals (LETS), Error Budget | MTBF, MTTD |
| 🧱 **Infrastructure health** | USE Method (CPU, Memory, Disk, Network) | Saturation, IOPS |
| 🔬 **Microservices debugging** | RED Method (Rate, Errors, Duration) | Trace Span Error Rate |

---

### By Team Role

| Role | Must-Know Metrics |
|---|---|
| **DevOps Engineer** | All DORA metrics, Pipeline metrics, USE Method, Availability |
| **SRE** | SLI/SLO/Error Budget, Four Golden Signals, MTTR, MTTD |
| **Platform Engineer** | CPU/Memory/Disk/Network, Saturation, Throughput, Scale-out Efficiency |
| **Security Engineer** | MTTD (security), MTTC, Vuln Count, Patch Compliance, Auth Failure Rate |
| **FinOps / Cloud Architect** | Cost per Request, CPPU, Resource Utilization Efficiency |
| **Engineering Manager** | DORA metrics, Test Coverage, Pipeline Success Rate, Lead Time |
| **Backend Developer** | Latency percentiles, Error Rate, Apdex, Test Coverage |

---

### Metric Decision Flowchart

```
START: What do you need to measure?
│
├── User Experience?
│   ├── Response time → Latency (p50/p95/p99) + Apdex
│   └── Is the service up? → Availability + SLI/SLO
│
├── Deployment / Release?
│   ├── Speed → Deployment Frequency + Lead Time for Changes
│   └── Quality → Change Failure Rate + MTTR
│
├── Incident Response?
│   ├── How fast found? → MTTD
│   ├── How fast fixed? → MTTR (Restore)
│   └── Root cause fixed? → MTTR (Resolve)
│
├── Infrastructure Health?
│   ├── Per resource → USE Method (Utilization, Saturation, Errors)
│   └── Per service → Four Golden Signals (LETS)
│
├── Security Posture?
│   ├── Threat detection → MTTD (security), Auth Failure Rate
│   └── Vulnerability mgmt → Vuln Count by Severity, Patch Compliance
│
└── Cost / Efficiency?
    ├── Cloud spend → Cost per Request, CPPU
    └── Waste → Resource Utilization Efficiency
```

---

## Appendix: Common Tools by Metric Category

| Category | Open Source Tools | Commercial Tools |
|---|---|---|
| Infrastructure Metrics | Prometheus, Grafana, Netdata | Datadog, New Relic, Dynatrace |
| APM / Latency / Traces | Jaeger, Zipkin, Tempo | Datadog APM, Elastic APM |
| Logs | Loki, ELK Stack, Fluentd | Splunk, Datadog Logs, Sumo Logic |
| Security Metrics | Wazuh, OSSEC, OpenVAS | CrowdStrike, Tenable, Rapid7 |
| CI/CD Metrics | GitLab CI, Tekton, ArgoCD | CircleCI, GitHub Actions (Advanced) |
| Load Testing | k6, Locust, Gatling, JMeter | BlazeMeter, LoadRunner |
| SLO Tracking | Sloth, OpenSLO, Pyrra | Nobl9, Datadog SLOs |
| FinOps / Cost | Kubecost, Infracost | AWS Cost Explorer, CloudHealth |

---

## Appendix: Key Formulas Cheat Sheet

```
DORA:
  Deployment Frequency   = Deployments / Time Period
  Lead Time              = Deploy Timestamp − First Commit Timestamp
  Change Failure Rate    = (Failed Deploys / Total Deploys) × 100
  MTTR                   = Total Downtime / Number of Incidents

Availability:
  Availability (%)       = (Uptime / Total Time) × 100
  Error Budget           = 100% − SLO Target
  SLI                    = (Good Requests / Total Requests) × 100

Performance:
  Throughput             = Total Requests / Time Period
  Apdex                  = (Satisfied + Tolerating/2) / Total

Errors:
  Error Rate             = (Error Responses / Total Requests) × 100
  MTBF                   = Operational Time / Number of Failures
  MTTD                   = Avg(Detection Time − Failure Start Time)

Infrastructure:
  CPU Util (%)           = (CPU Time Used / Total CPU Time) × 100
  Memory Util (%)        = (Used Memory / Total Memory) × 100
  Bandwidth Util (%)     = (Current Traffic / Link Capacity) × 100

Security:
  Patch Compliance (%)   = (Patched Systems / Total Systems) × 100
  Auth Failure Rate (%)  = (Failed Logins / Total Attempts) × 100

CI/CD:
  Pipeline Success (%)   = (Successful Runs / Total Runs) × 100
  Test Coverage (%)      = (Lines Covered / Total Lines) × 100
  Flaky Test Rate (%)    = (Flaky Tests / Total Tests) × 100

Cost:
  Cost per Request       = Total Infra Cost / Total Requests
  CPPU                   = Total Infra Cost / Active Users
  Utilization Efficiency = (Actual Usage / Provisioned Capacity) × 100
```

---

## 12. GPU Metrics

> GPU metrics are critical for ML/AI workloads, rendering pipelines, video transcoding, and any compute-intensive platform. Tools: **NVIDIA DCGM**, **nvidia-smi**, **Prometheus DCGM Exporter**, **Grafana**.

---

### 12.1 GPU Utilization

**Definition**: Percentage of time the GPU's streaming multiprocessors (SMs) were busy executing at least one warp during a sample window.

**Formula**:
```
GPU Utilization (%) = (Active SM Cycles / Total Elapsed Cycles) × 100
```

**Thresholds**:
| Range | Status | Action |
|---|---|---|
| 0–20% | 🔵 Idle / Wasted | GPU likely over-provisioned or workload stalled |
| 20–60% | 🟡 Moderate | Normal for intermittent workloads |
| 60–85% | 🟢 Healthy | Good utilization for training/inference |
| 85–100% | 🚀 Peak | Optimal for sustained training jobs |

**Example**:
```
nvidia-smi output:
  GPU 0 Utilization: 94%   → Training job is well utilized
  GPU 1 Utilization: 3%    → Idle, potentially deallocate
```

**When to use**:
- Right-sizing GPU instance types (A100 vs T4 vs V100)
- ML training job monitoring
- Detecting idle GPUs in Kubernetes GPU node pools
- Cost optimization (GPU hours are expensive)

---

### 12.2 GPU Memory Utilization

**Definition**: Percentage of GPU VRAM (Video RAM) currently in use.

**Formula**:
```
GPU Memory Utilization (%) = (Used VRAM / Total VRAM) × 100
```

**Key Metrics**:
| Metric | Description |
|---|---|
| `memory.used` | VRAM currently allocated (MiB/GiB) |
| `memory.free` | Available VRAM |
| `memory.total` | Total VRAM on device |
| Memory Utilization % | Used / Total × 100 |

**Example**:
```
nvidia-smi:
  Memory Used:  22528 MiB
  Memory Total: 24576 MiB  (A100 40GB)

Memory Utilization = (22528 / 24576) × 100 = 91.7%
```

**OOM Risk**:
```
> 95% VRAM → High risk of Out-of-Memory (OOM) errors
OOM kills the training job with CUDA out of memory error
```

**When to use**:
- Tuning batch sizes for ML training
- Preventing OOM crashes during inference
- Kubernetes GPU memory limit configuration
- Model quantization decisions (FP32 → FP16 → INT8)

---

### 12.3 GPU Temperature

**Definition**: Core die temperature of the GPU in degrees Celsius.

**Formula**:
```
Read directly from NVML (NVIDIA Management Library) or nvidia-smi
Metric: gpu_temperature_celsius
```

**Thresholds (NVIDIA GPUs)**:
| Range | Status | Risk |
|---|---|---|
| < 60°C | ✅ Cool | Normal |
| 60–80°C | 🟡 Warm | Monitor, ensure airflow |
| 80–87°C | ⚠️ Hot | Performance throttling begins |
| > 87°C | 🔴 Critical | Thermal throttle, risk of damage |

**Example**:
```
GPU 0: 72°C  → Warm but within limits
GPU 1: 89°C  → Throttling! Check cooling / fan speed
```

**When to use**:
- Data center cooling and airflow monitoring
- Detecting throttling that silently slows ML training
- Hardware health alerts for bare-metal GPU servers

---

### 12.4 GPU Power Consumption

**Definition**: Instantaneous power draw of the GPU in Watts.

**Formula**:
```
Power Efficiency = Throughput (FLOPS or tokens/sec) / Power Draw (Watts)
```

**Key Metrics**:
| Metric | Description |
|---|---|
| `power.draw` | Current power consumption (W) |
| `power.limit` | Max TDP (Thermal Design Power) |
| Power Utilization % | Draw / Limit × 100 |

**Example**:
```
A100 SXM:
  Power Draw:  380W
  TDP Limit:   400W
  Power Util = (380 / 400) × 100 = 95% → Near maximum performance
```

**When to use**:
- Data center power budgeting and rack planning
- Energy cost optimization in cloud/on-prem
- Comparing GPU efficiency for model inference

---

### 12.5 GPU SM Clock Speed

**Definition**: The clock frequency (MHz) of the streaming multiprocessors — directly affects compute throughput.

**Formula**:
```
Actual Throughput = Theoretical Peak TFLOPS × (Actual Clock / Base Clock) × GPU Utilization %
```

**Example**:
```
A100 base clock:   1065 MHz
A100 boost clock:  1410 MHz
Current clock:      980 MHz  → Thermal throttling is reducing clock!

Expected peak at 1410MHz:  77.6 TFLOPS
Actual at 980MHz:          54.0 TFLOPS → 30% performance loss
```

**When to use**:
- Diagnosing silent performance degradation in training jobs
- Validating GPU boost clocks are sustained under load
- Comparing cloud GPU instance actual vs advertised performance

---

### 12.6 Tensor Core / CUDA Core Utilization

**Definition**: The fraction of time Tensor Cores (for matrix multiply) or CUDA Cores (for general compute) are actively executing.

**Key DCGM Metrics**:
| Metric | Description |
|---|---|
| `DCGM_FI_PROF_TENSOR_ACTIVE` | Fraction of cycles Tensor Cores are active |
| `DCGM_FI_PROF_SM_ACTIVE` | Fraction of cycles SMs have at least 1 warp |
| `DCGM_FI_PROF_SM_OCCUPANCY` | Fraction of warp slots filled |

**Example**:
```
Tensor Core Active: 78%  → Good for FP16/BF16 matrix ops
SM Active:          91%
SM Occupancy:       65%  → Room to increase batch size
```

**When to use**:
- ML model optimization (ensure ops are Tensor Core eligible)
- Debugging low GPU utilization despite high SM active rates
- Mixed-precision training validation

---

### 12.7 NVLink / PCIe Bandwidth

**Definition**: Data transfer rate between GPUs (NVLink) or between GPU and CPU (PCIe).

**Formula**:
```
Bandwidth Utilization (%) = (Actual Transfer Rate / Max Bandwidth) × 100
```

**Reference Bandwidths**:
| Interconnect | Max Bandwidth |
|---|---|
| PCIe 4.0 x16 | ~32 GB/s |
| PCIe 5.0 x16 | ~64 GB/s |
| NVLink 3.0 (A100) | 600 GB/s bidirectional |
| NVLink 4.0 (H100) | 900 GB/s bidirectional |

**Example**:
```
Multi-GPU training:
  NVLink TX: 280 GB/s
  NVLink RX: 275 GB/s
  Utilization = (280 / 600) × 100 = 46.7%  → Headroom available

PCIe data loading bottleneck:
  PCIe BW: 30 GB/s / 32 GB/s = 93.7% → SATURATED, data loader is bottleneck!
```

**When to use**:
- Diagnosing multi-GPU training communication bottlenecks
- Detecting CPU-to-GPU data loading bottlenecks
- Validating NVLink topology in DGX / HGX systems

---

### 12.8 GPU Inference Throughput

**Definition**: Number of model inferences (predictions) per second.

**Formula**:
```
Inference Throughput (RPS) = Total Inferences / Time Period
GPU Throughput Efficiency = Actual RPS / Theoretical Max RPS × 100
```

**Example (LLM inference)**:
```
Model: LLaMA-3 8B on A100
Target: 100 tokens/sec
Actual: 87 tokens/sec

Efficiency = (87 / 100) × 100 = 87%

Latency per token: 11.5ms  → Acceptable for streaming UI
```

**When to use**:
- ML serving platform capacity planning
- Comparing inference frameworks (TensorRT vs vLLM vs ONNX)
- Auto-scaling GPU inference deployments

---

## 13. Deep CPU Metrics

> Beyond simple utilization %, modern systems expose detailed CPU performance data via hardware performance counters (perf, eBPF, PMU). These are critical for performance engineering and bottleneck analysis.

---

### 13.1 CPU Utilization by State

**Definition**: CPU time is broken into distinct states — understanding which state time is spent in reveals the actual bottleneck.

**CPU Time States**:
| State | Symbol | Meaning |
|---|---|---|
| User | `us` | Time running userspace processes |
| System | `sy` | Time running kernel code |
| I/O Wait | `wa` | Time waiting for I/O to complete |
| Idle | `id` | CPU has nothing to do |
| Steal | `st` | Time stolen by hypervisor (VMs only) |
| Soft IRQ | `si` | Software interrupt handling |
| Hard IRQ | `hi` | Hardware interrupt handling |
| Nice | `ni` | Userspace processes at low priority |

**Formula**:
```
Total CPU Time = us + sy + wa + id + st + si + hi + ni  (always = 100%)

Effective Utilization = us + sy  (actual work)
I/O Bound indicator  = wa > 10%  (waiting on disk/network)
VM Tax indicator     = st > 5%   (hypervisor stealing CPU)
```

**Example (top / vmstat output)**:
```
%Cpu(s): 45.2 us,  8.1 sy,  0.0 ni, 38.4 id, 12.3 wa,  0.0 hi,  0.8 si,  4.2 st

Analysis:
  - wa=12.3% → I/O bottleneck (check disk or network)
  - st=4.2%  → Significant hypervisor steal (consider dedicated host)
  - us=45.2% → Moderate user load
```

**When to use**:
- Distinguishing CPU-bound vs I/O-bound performance problems
- Diagnosing VM performance issues (steal time)
- Kernel tuning and interrupt balancing

---

### 13.2 CPU Run Queue Length (Load Average)

**Definition**: The number of processes waiting to be scheduled on a CPU. If run queue > CPU cores, CPUs are saturated.

**Formula**:
```
Load Average (Linux) = Exponentially weighted moving average of:
  - Processes currently running
  - Processes waiting to run (runnable)
  - Processes in uninterruptible sleep (D state)

Saturation indicator: Load Average > Number of CPU Cores
```

**Output**: `load average: 1-min, 5-min, 15-min`

**Example**:
```
Server: 8 CPU cores

uptime output: load average: 3.2, 4.8, 6.1

Analysis:
  1-min  (3.2 / 8):   40%  → Fine right now
  5-min  (4.8 / 8):   60%  → Increasing load
  15-min (6.1 / 8):   76%  → Trend is concerning, investigate

If load average > 8 (core count) → CPUs are oversubscribed
```

**When to use**:
- First-look health check on any Linux server
- Alert threshold: load > (cores × 0.85) for sustained periods
- Kubernetes node affinity and scheduling decisions

---

### 13.3 Context Switch Rate

**Definition**: The rate at which the OS switches the CPU from one process/thread to another. High rates indicate scheduling overhead.

**Formula**:
```
Context Switch Rate = Total Context Switches / Time Period (per second)

Voluntary:    Process yields CPU (waiting for I/O, sleep)
Involuntary:  Scheduler preempts process (time slice expired)
```

**Benchmarks**:
| Rate | Assessment |
|---|---|
| < 1,000 /sec/core | Low load |
| 1,000–10,000 /sec/core | Normal |
| 10,000–100,000 /sec/core | High — investigate |
| > 100,000 /sec/core | 🔴 Excessive — thread contention |

**Example**:
```
vmstat 1 output (cs column):
  cs: 45,230 /sec on 4-core host

Per core = 45,230 / 4 = 11,307 /sec/core → High, investigate thread count

Likely cause: Too many threads, use async/event-driven design
```

**When to use**:
- Java/Go/Python thread tuning
- Diagnosing performance degradation under high concurrency
- Kubernetes container thread limit tuning

---

### 13.4 CPU Cache Hit Rate

**Definition**: Percentage of memory accesses served from CPU cache (L1/L2/L3) vs. main RAM. Cache misses are expensive (100–200 CPU cycles each).

**Cache Hierarchy Latency**:
| Cache Level | Size (typical) | Latency |
|---|---|---|
| L1 Cache | 32–64 KB | ~4 cycles (1–2 ns) |
| L2 Cache | 256 KB – 1 MB | ~12 cycles (3–5 ns) |
| L3 Cache (LLC) | 8–64 MB | ~40 cycles (10–20 ns) |
| Main RAM (DRAM) | GBs | ~200 cycles (60–100 ns) |
| NVMe SSD | TBs | ~50,000 ns |

**Formula**:
```
Cache Hit Rate (%) = (Cache Hits / Total Memory Accesses) × 100
Cache Miss Rate (%) = 100 − Cache Hit Rate

Measured via: perf stat, Intel VTune, AMD uProf
```

**Example**:
```
perf stat ./my_app output:
  L1 cache misses:      1,234,567
  L1 cache references:  98,765,432

L1 Hit Rate = ((98,765,432 − 1,234,567) / 98,765,432) × 100 = 98.75% ✅

If L3 hit rate < 90% → Memory access pattern is poor (cache thrashing)
```

**When to use**:
- High-performance C/C++/Rust code optimization
- Database buffer pool tuning
- Identifying cache-unfriendly data structures

---

### 13.5 Instructions Per Cycle (IPC)

**Definition**: The average number of CPU instructions executed per clock cycle. Higher IPC = more efficient CPU usage.

**Formula**:
```
IPC = Instructions Retired / CPU Cycles Elapsed

Measured via: perf stat, hardware performance counters (PMU)
```

**Benchmarks**:
| IPC Value | Assessment |
|---|---|
| > 3.0 | Excellent (well-optimized, vectorized code) |
| 1.5–3.0 | Good |
| 0.5–1.5 | Mediocre (cache misses or branch mispredictions) |
| < 0.5 | Poor (severely memory-bound or stalled pipeline) |

**Example**:
```
perf stat -e instructions,cycles ./server
  Instructions:  8,450,000,000
  Cycles:        5,200,000,000

IPC = 8,450,000,000 / 5,200,000,000 = 1.625  → Decent, room for improvement
```

**When to use**:
- Low-level performance engineering
- Comparing CPU efficiency before/after optimization
- Evaluating SIMD/vectorization gains

---

### 13.6 CPU Throttling (Kubernetes)

**Definition**: In Kubernetes, CPU throttling occurs when a container exceeds its CPU limit. The container is "throttled" (paused) until the next quota period.

**Formula**:
```
CPU Throttling Rate (%) = 
  (throttled_periods / total_periods) × 100

K8s Prometheus metric:
  container_cpu_cfs_throttled_periods_total
  container_cpu_cfs_periods_total
```

**Example**:
```
container_cpu_cfs_throttled_periods_total = 4,500
container_cpu_cfs_periods_total           = 10,000

Throttling Rate = (4,500 / 10,000) × 100 = 45% → CRITICAL, increase CPU limit!
```

**Throttling Impact**:
```
Even 5% throttling can cause:
  - p99 latency spikes of 10–50×
  - Timeout cascades in microservices
  - Go GC pauses lasting seconds
```

**When to use**:
- Kubernetes container CPU limit tuning
- Diagnosing latency spikes in containerized services
- Kubernetes VPA (Vertical Pod Autoscaler) input metric

---

### 13.7 CPU Frequency Scaling

**Definition**: Modern CPUs dynamically adjust clock speed based on load (P-states) and thermal constraints (thermal throttling).

**Key States**:
| State | Description |
|---|---|
| P0 | Maximum performance (full boost clock) |
| P1–Pn | Reduced frequency / voltage states |
| C0 | CPU executing instructions (active) |
| C1–C6 | Sleep states (progressively deeper idle) |

**Formula**:
```
Frequency Scaling Ratio = Current Clock / Maximum Boost Clock × 100
```

**Example**:
```
CPU: Intel Xeon Gold 6338 (max boost: 3.2 GHz)
Current freq under load: 2.6 GHz

Frequency Ratio = (2.6 / 3.2) × 100 = 81.25% → Thermal limiting in play

Check: cpupower frequency-info | grep "current CPU frequency"
```

**When to use**:
- Diagnosing thermal throttling on bare-metal servers
- Validating performance governor settings (`performance` vs `powersave`)
- Kubernetes node performance tuning

---

## 14. Application-Specific Metrics

> Every application type exposes its own unique performance signals. Below are the most important metrics per technology stack.

---

### 14.1 Web Server Metrics (Nginx / Apache / HAProxy)

**Key Metrics**:
| Metric | Formula / Source | Target |
|---|---|---|
| Active Connections | `nginx_connections_active` | < configured worker_connections |
| Requests per Second | `nginx_http_requests_total` rate | Monitor trend |
| Connection Queue Depth | `accept_mutex` overflow | Should be 0 |
| Worker CPU % | Per-worker CPU usage | < 80% per worker |
| Upstream Response Time | `$upstream_response_time` | < 200ms p99 |
| Upstream Error Rate | 5xx from upstream / Total | < 0.1% |
| Cache Hit Rate | `nginx_cache_hit_ratio` | > 80% for static assets |

**Example Nginx status**:
```
Active connections: 847
server accepts handled requests
 1000234 1000234 5430129

Request rate = 5,430,129 / uptime_seconds = ~1,250 RPS
Accepts = Handled → No dropped connections ✅
```

**When to use**:
- Web server capacity planning
- CDN cache effectiveness analysis
- Load balancer health and upstream monitoring

---

### 14.2 Database Metrics (PostgreSQL / MySQL)

**Key Metrics**:
| Metric | Formula | Target |
|---|---|---|
| Queries per Second (QPS) | `pg_stat_database.xact_commit` rate | Baseline dependent |
| Query Latency (p99) | Slow query log / `pg_stat_statements` | < 100ms for OLTP |
| Active Connections | `pg_stat_activity` count | < `max_connections × 0.8` |
| Connection Wait Time | Lock wait duration | < 50ms |
| Cache Hit Rate | Buffer Pool Hit Rate | > 99% for OLTP |
| Index Hit Rate | Index scans / Total scans | > 95% |
| Replication Lag | Primary LSN − Replica LSN | < 1 second |
| Dead Tuple Ratio | Dead tuples / Total tuples | < 10% (trigger VACUUM) |
| Lock Wait Count | `pg_locks` blocked queries | Should be 0 in steady state |
| TPS (Transactions/sec) | Committed txns / second | Baseline dependent |

**Buffer Pool Hit Rate Formula**:
```
Buffer Hit Rate (%) = 
  (blks_hit / (blks_hit + blks_read)) × 100

PostgreSQL query:
  SELECT 
    sum(blks_hit) * 100.0 / (sum(blks_hit) + sum(blks_read)) AS hit_rate
  FROM pg_stat_database;
```

**Example**:
```
blks_hit:  9,870,000
blks_read:    130,000

Hit Rate = (9,870,000 / 10,000,000) × 100 = 98.7% ✅

If < 95% → Increase shared_buffers or add RAM
```

**Replication Lag Formula**:
```
Replication Lag (bytes) = 
  pg_current_wal_lsn() − sent_lsn  (on primary)

Lag in seconds:
  EXTRACT(EPOCH FROM (now() − pg_last_xact_replay_timestamp())) AS lag_sec
```

**When to use**:
- Database performance tuning and index optimization
- Read replica lag monitoring for consistency
- Connection pooling (PgBouncer) sizing decisions

---

### 14.3 Redis / Cache Metrics

**Key Metrics**:
| Metric | Formula / Command | Target |
|---|---|---|
| Cache Hit Rate | `keyspace_hits / (keyspace_hits + keyspace_misses)` | > 90% |
| Memory Usage | `used_memory / maxmemory` | < 80% |
| Eviction Rate | `evicted_keys` rate | Should be ~0 |
| Connected Clients | `connected_clients` | < `maxclients × 0.8` |
| Ops per Second | `instantaneous_ops_per_sec` | Baseline dependent |
| Replication Lag | `master_repl_offset − slave_repl_offset` | < 100KB |
| Blocked Clients | `blocked_clients` | Should be 0 |
| Key Expiry Rate | `expired_keys` per second | Monitor for spikes |

**Cache Hit Rate Formula**:
```
Hit Rate (%) = 
  keyspace_hits / (keyspace_hits + keyspace_misses) × 100

Redis CLI: INFO stats → keyspace_hits, keyspace_misses
```

**Example**:
```
redis-cli INFO stats:
  keyspace_hits:   8,750,000
  keyspace_misses:   250,000

Hit Rate = (8,750,000 / 9,000,000) × 100 = 97.2% ✅

Eviction policy: allkeys-lru
Evicted keys: 45,000  → Cache is too small, increase maxmemory!
```

**When to use**:
- Session store and object cache sizing
- Detecting cache stampede events (miss rate spike)
- Redis Cluster shard balancing

---

### 14.4 Message Queue Metrics (Kafka / RabbitMQ / SQS)

**Key Metrics**:
| Metric | Formula | Target |
|---|---|---|
| Consumer Lag | Latest Offset − Consumer Offset | < defined SLA per topic |
| Throughput (Producer) | Messages produced / second | Baseline |
| Throughput (Consumer) | Messages consumed / second | ≥ Producer rate |
| Message Age (Oldest) | now() − oldest_unconsumed_msg_timestamp | < SLA |
| Partition Imbalance | Std dev of messages across partitions | < 10% |
| Replication Lag | ISR lag behind leader | Should be 0 |
| Under-Replicated Partitions | Count of partitions with ISR < replication factor | Must be 0 |
| Dead Letter Queue (DLQ) Depth | Messages in DLQ | Alert on any growth |

**Consumer Lag Formula (Kafka)**:
```
Consumer Lag = Log End Offset − Consumer Current Offset

kafka-consumer-groups.sh --describe --group my-service

TOPIC         PARTITION  CURRENT-OFFSET  LOG-END-OFFSET  LAG
orders        0          4,500,000       4,502,300       2,300
orders        1          3,200,000       3,204,100       4,100

Total Lag = 2,300 + 4,100 = 6,400 messages behind
```

**When to use**:
- Auto-scaling consumers based on lag (KEDA)
- Detecting slow consumers before they cause cascading failures
- Kafka cluster health and broker monitoring

---

### 14.5 JVM / Java Application Metrics

**Key Metrics**:
| Metric | Description | Target |
|---|---|---|
| Heap Usage | `jvm_memory_used_bytes{area="heap"}` | < 80% of max heap |
| GC Pause Time (p99) | Duration of stop-the-world GC pauses | < 200ms |
| GC Throughput | % of time NOT doing GC | > 95% |
| Thread Count | Active JVM threads | Monitor for leaks |
| Non-Heap Memory | Metaspace, Code Cache | Monitor for growth |
| Class Loading Rate | Classes loaded / sec | Should stabilize |
| JIT Compilation Time | CPU time in JIT compiler | Should decrease over time |

**GC Throughput Formula**:
```
GC Throughput (%) = 
  (1 − (Total GC Time / Total Elapsed Time)) × 100

If GC Throughput < 90% → GC is consuming too much CPU
```

**Example**:
```
Spring Boot app over 5 minutes:
  Total time:    300,000ms
  Total GC time: 18,000ms

GC Throughput = (1 − (18,000 / 300,000)) × 100 = 94% ← Borderline
GC Pause p99 = 350ms  → Users experiencing noticeable delays!

Fix: Switch from CMS to G1GC or ZGC for lower pause times
```

**Heap Usage Pattern Analysis**:
```
Healthy:    Sawtooth pattern (grows, GC drops it down, repeats)
Leak:       Upward trend, GC cannot bring it fully down
OOM risk:   Heap at > 90% consistently
```

**When to use**:
- Java microservice performance tuning
- GC algorithm selection (G1GC vs ZGC vs Shenandoah)
- Diagnosing OutOfMemoryError root causes

---

### 14.6 Node.js / JavaScript Application Metrics

**Key Metrics**:
| Metric | Description | Target |
|---|---|---|
| Event Loop Lag | Delay in event loop processing | < 100ms p99 |
| Event Loop Utilization (ELU) | % time event loop is active | < 70% sustained |
| Heap Used | V8 heap memory used | < 80% of heap limit |
| Active Handles | Open file descriptors, sockets | Monitor for leaks |
| Active Requests | Pending async I/O | Should complete promptly |
| GC Duration | V8 GC pause duration | < 50ms |

**Event Loop Lag Formula**:
```
Event Loop Lag = Actual callback delay − Expected callback delay

Example:
  setTimeout(() => {}, 10ms)
  Actual execution: 85ms
  EL Lag = 85 − 10 = 75ms  → Event loop is blocked!
```

**Event Loop Utilization**:
```javascript
const { performance, PerformanceObserver } = require('perf_hooks');
const { eventLoopUtilization } = performance;

// ELU > 0.85 = Event loop over-saturated
const elu = eventLoopUtilization();
console.log(`ELU: ${(elu.utilization * 100).toFixed(1)}%`);
```

**When to use**:
- Diagnosing slow Node.js APIs despite low CPU
- Detecting blocking I/O or CPU-intensive callbacks
- Choosing between threading (worker_threads) vs async patterns

---

### 14.7 Kubernetes / Container Metrics

**Key Metrics**:
| Metric | Formula / Prometheus Query | Target |
|---|---|---|
| Pod Restart Count | `kube_pod_container_status_restarts_total` | < 5 in 1h |
| CPU Throttling Rate | `container_cpu_cfs_throttled_periods_total / container_cpu_cfs_periods_total` | < 5% |
| OOMKill Count | `container_oom_events_total` | Must be 0 |
| Pod Pending Time | Time from creation to Running state | < 30 sec |
| Node Pressure | NodeMemoryPressure / NodeDiskPressure | Must be False |
| Cluster CPU Requests % | `sum(kube_pod_container_resource_requests{resource="cpu"}) / sum(knode_node_status_allocatable{resource="cpu"})` | < 80% |
| HPA Desired vs Current | `kube_horizontalpodautoscaler_status_desired_replicas` vs current | Should converge |
| PVC Usage | `kubelet_volume_stats_used_bytes / kubelet_volume_stats_capacity_bytes` | < 80% |

**Pod Restart Rate**:
```
Alert condition (PromQL):
  increase(kube_pod_container_status_restarts_total[1h]) > 5

High restarts indicate:
  - OOMKill (increase memory limit or fix leak)
  - Liveness probe failures (fix probe or app startup time)
  - Crash loop (application exception at startup)
```

**Node Resource Pressure**:
```
Cluster CPU Request Ratio:
  sum(kube_pod_container_resource_requests{resource="cpu"})
  /
  sum(kube_node_status_allocatable{resource="cpu"})
  × 100

If > 80% → Cluster is full, add nodes or reduce requests
If < 30% → Cluster is over-provisioned, scale down nodes
```

**When to use**:
- Kubernetes cluster capacity planning
- HPA/VPA auto-scaling configuration
- Detecting noisy neighbor pods on shared nodes

---

### 14.8 HTTP API / Microservice Metrics

**Key Metrics by Layer**:
| Layer | Metric | Target |
|---|---|---|
| Gateway / Ingress | Total RPS, SSL Handshake Time | Baseline |
| Service | Request Rate, Error Rate, Latency (RED) | Error < 0.1%, p99 < SLO |
| Dependency | Downstream error rate, timeout rate | < 0.5% |
| Circuit Breaker | Open/Half-Open state duration | Alert on Open state |

**HTTP Status Distribution Formula**:
```
Success Rate (%) = HTTP 2xx count / Total requests × 100
Client Error Rate (%) = HTTP 4xx count / Total requests × 100
Server Error Rate (%) = HTTP 5xx count / Total requests × 100
```

**Example breakdown**:
```
Requests in 1 hour: 1,000,000
  2xx:  982,000  → 98.2% success
  3xx:   10,000  → 1.0%  redirects
  4xx:    5,500  → 0.55% client errors (bad inputs)
  5xx:    2,500  → 0.25% server errors  ← Alert threshold!
```

**Dependency Health Formula**:
```
Downstream Error Rate = 
  Errors calling service B / Total calls to service B × 100

Timeout Rate = 
  Timed-out calls / Total calls × 100

If timeout rate > 1% → Circuit breaker should trigger
```

**When to use**:
- API gateway and service mesh dashboards (Envoy, Istio)
- SLO tracking for individual endpoints
- Circuit breaker threshold tuning (Resilience4j, Hystrix)

---

### 14.9 Elasticsearch / OpenSearch Metrics

**Key Metrics**:
| Metric | Description | Target |
|---|---|---|
| Search Latency (p99) | Time to execute search query | < 200ms |
| Indexing Rate | Documents indexed / second | Baseline |
| Indexing Latency | Time to index a document | < 50ms |
| JVM Heap Usage | ES runs on JVM | < 75% of heap |
| GC Old Gen Collections | Full GC frequency | < 1/min |
| Shard Size | Average shard size | 20–50 GB ideal |
| Rejected Threads | Bulk queue rejections | Must be 0 |
| Unassigned Shards | `_cluster/health` red status | Must be 0 |
| Index Merge Time | Background merge operations | < 5% of indexing time |

**Cluster Health States**:
```
🟢 Green  = All primary and replica shards assigned
🟡 Yellow = All primary shards assigned, some replicas unassigned
🔴 Red    = Some primary shards unassigned → DATA LOSS RISK
```

**When to use**:
- Log aggregation (ELK stack) performance tuning
- Security SIEM platform monitoring
- Search relevance and latency optimization

---

### 14.10 Linux OS / Kernel Metrics

**Key Metrics**:
| Category | Metric | Command | Target |
|---|---|---|---|
| CPU | Load Average | `uptime`, `top` | < num_cores |
| CPU | Context Switches/sec | `vmstat` cs column | < 10K/core/sec |
| CPU | Interrupts/sec | `vmstat` in column | Monitor for spikes |
| Memory | Available Memory | `free -h` | > 20% free |
| Memory | Swap Usage | `vmstat` swpd | Ideally 0 |
| Disk | iowait % | `iostat` | < 10% |
| Disk | Disk Latency | `iostat -x` await | < 10ms HDD, < 1ms SSD |
| Disk | Disk Queue Depth | `iostat -x` aqu-sz | < 1 for SSD |
| Network | Packet Drops | `ip -s link` | 0 drops |
| Network | Retransmit Rate | `ss -s`, netstat | < 0.1% |
| File System | Open File Descriptors | `lsof \| wc -l` | < `fs.file-max` |
| Kernel | OOM Kill Events | `dmesg \| grep oom` | 0 events |

**Disk Latency Formula**:
```
Average I/O Latency (await) = 
  Total time requests spent in queue + service time
  / Number of I/O requests

iostat -x 1:
  Device  r/s  w/s  rkB/s  wkB/s  await  aqu-sz  util
  sda     120   80  4800  3200    8.5    0.9     72%

await=8.5ms → Acceptable for HDD, borderline for database workloads
util=72%    → Disk approaching saturation (> 80% = warning)
```

**Network Retransmit Rate**:
```
Retransmit Rate (%) = 
  TCP Retransmissions / Total TCP Segments Sent × 100

> 0.5% → Network quality issue (congestion, packet loss)
> 2%   → Critical: significant application performance impact
```

**When to use**:
- Bare-metal and VM infrastructure monitoring
- OS-level performance troubleshooting
- Kubernetes node health assessment

---

### Appendix: GPU Metrics Cheat Sheet

```
GPU:
  GPU Utilization (%)      = Active SM Cycles / Total Cycles × 100
  GPU Memory Usage (%)     = Used VRAM / Total VRAM × 100
  Power Efficiency         = Throughput / Power Draw (W)
  NVLink BW Util (%)       = Actual Transfer Rate / 600 GB/s × 100
  Inference Throughput     = Total Inferences / Time Period
  Tensor Core Active       = DCGM_FI_PROF_TENSOR_ACTIVE (0.0–1.0)
```

### Appendix: CPU Deep Metrics Cheat Sheet

```
CPU Deep Metrics:
  IPC                      = Instructions Retired / CPU Cycles
  Cache Hit Rate (%)       = Cache Hits / Total Accesses × 100
  Context Switch Rate      = Switches / Second / Core
  Load Average Ratio       = Load Average / CPU Core Count
  K8s CPU Throttling (%)   = throttled_periods / total_periods × 100
  GC Throughput (%)        = (1 − GC Time / Total Time) × 100
```

### Appendix: Application Metrics Cheat Sheet

```
Application Metrics:
  DB Buffer Hit Rate (%)   = blks_hit / (blks_hit + blks_read) × 100
  Redis Hit Rate (%)       = keyspace_hits / (hits + misses) × 100
  Kafka Consumer Lag       = Log End Offset − Consumer Offset
  JVM GC Throughput (%)    = (1 − GC Time / Total Time) × 100
  Node.js EL Lag (ms)      = Actual delay − Expected delay
  K8s CPU Throttle (%)     = throttled_periods / total_periods × 100
  HTTP Success Rate (%)    = 2xx responses / Total requests × 100
  ES Cluster Health        = Green/Yellow/Red (from _cluster/health)
```

---

## 15. Docker Metrics

> Docker exposes container-level resource metrics via the Docker stats API, cAdvisor, and the Prometheus Docker metrics exporter. These metrics operate at the **container runtime** level, below Kubernetes orchestration.

---

### 15.1 Container CPU Usage

**Definition**: CPU time consumed by a Docker container, expressed as a percentage of available host CPU.

**Formula**:
```
CPU Usage (%) =
  (delta_container_cpu_usage / delta_system_cpu_usage) × num_cpus × 100

Where:
  delta_container_cpu_usage = current_cpu_total − previous_cpu_total
  delta_system_cpu_usage    = current_system_cpu − previous_system_cpu
```

**Docker Stats Fields**:
| Field | Description |
|---|---|
| `cpu_stats.cpu_usage.total_usage` | Container total CPU nanoseconds |
| `cpu_stats.system_cpu_usage` | System-wide CPU nanoseconds |
| `cpu_stats.online_cpus` | Number of CPUs available to container |

**Example**:
```bash
docker stats --no-stream

CONTAINER ID   NAME       CPU %   MEM USAGE / LIMIT     MEM %
a1b2c3d4e5f6   api-svc    34.7%   512MiB / 2GiB         25.0%
f6e5d4c3b2a1   db-svc      8.2%   1.8GiB / 4GiB         45.0%

api-svc at 34.7% → Healthy
db-svc at 8.2%   → Low, under-utilized or idle
```

**CPU Throttling (cgroups)**:
```
Throttled Time = time container was throttled by cgroup CPU quota
Throttle Rate (%) = throttled_time / (throttled_time + elapsed_time) × 100

> 10% throttle rate → Container CPU limit too low
```

**When to use**:
- Right-sizing Docker container CPU limits
- Identifying containers consuming disproportionate CPU on shared hosts
- Detecting noisy neighbor containers

---

### 15.2 Container Memory Usage

**Definition**: Memory consumed by a container including working set, cache, and RSS.

**Key Memory Fields**:
| Field | Description | Include in Limit? |
|---|---|---|
| `rss` | Resident Set Size (actual used RAM) | Yes |
| `cache` | Page cache (reclaimable) | Often excluded |
| `swap` | Swap space used | Yes |
| `working_set` | rss + cache − inactive_file | Best measure |
| `memory.limit_in_bytes` | Container memory hard limit | — |

**Formula**:
```
Memory Usage (%) = (working_set_bytes / memory_limit_bytes) × 100

Working Set = memory.usage_in_bytes − memory.stat.inactive_file
```

**Example**:
```
Container limit:   2 GiB = 2,147,483,648 bytes
memory.usage_in_bytes:       1,800,000,000
memory.stat.inactive_file:     300,000,000

Working Set = 1,800,000,000 − 300,000,000 = 1,500,000,000 bytes = 1.4 GiB
Memory Usage % = (1,500,000,000 / 2,147,483,648) × 100 = 69.9% ✅

OOM Kill risk when Working Set approaches limit (>90%)
```

**OOM Kill Detection**:
```bash
docker inspect <container> | grep OOMKilled
# "OOMKilled": true → Container was killed by kernel OOM

# Also visible in:
dmesg | grep "Out of memory"
/sys/fs/cgroup/memory/<container>/memory.oom_control
```

**When to use**:
- Setting correct `--memory` limits in Docker run/Compose
- Preventing OOM kills in production containers
- Memory leak detection in long-running containers

---

### 15.3 Container Network I/O

**Definition**: Bytes and packets transmitted/received by a container's network interfaces.

**Key Metrics**:
| Metric | Description |
|---|---|
| `networks.eth0.rx_bytes` | Bytes received |
| `networks.eth0.tx_bytes` | Bytes transmitted |
| `networks.eth0.rx_packets` | Packets received |
| `networks.eth0.tx_packets` | Packets transmitted |
| `networks.eth0.rx_dropped` | Inbound dropped packets |
| `networks.eth0.tx_dropped` | Outbound dropped packets |
| `networks.eth0.rx_errors` | Receive errors |

**Formula**:
```
Network Throughput (MB/s) = delta_bytes / delta_time / 1,048,576
Packet Drop Rate (%) = dropped_packets / total_packets × 100
```

**Example**:
```
Time period: 10 seconds
  rx_bytes delta: 52,428,800  (50 MB)
  tx_bytes delta: 20,971,520  (20 MB)
  rx_dropped:     0
  tx_dropped:     0

RX Throughput = 50 MB / 10s = 5 MB/s
TX Throughput = 20 MB / 10s = 2 MB/s
Drop Rate = 0% ✅
```

**When to use**:
- Detecting bandwidth-hungry containers on shared Docker hosts
- Diagnosing inter-container communication bottlenecks
- Validating network policy effectiveness in Docker networks

---

### 15.4 Container Disk I/O

**Definition**: Read and write operations performed by a container to block storage devices.

**Key Metrics**:
| Metric | Source | Description |
|---|---|---|
| `blkio.io_service_bytes_recursive` | Docker stats | Bytes read/written |
| `blkio.io_serviced_recursive` | Docker stats | Number of I/O operations |
| `blkio.io_wait_time_recursive` | cAdvisor | Time waiting for I/O |
| `blkio.io_queue_recursive` | cAdvisor | Average I/O queue length |

**Formula**:
```
Read Throughput  (MB/s) = delta_read_bytes  / delta_time / 1,048,576
Write Throughput (MB/s) = delta_write_bytes / delta_time / 1,048,576
IOPS             = delta_io_ops / delta_time
```

**Example**:
```
docker stats output:
  BLOCK I/O:  450MB / 120MB
                ↑         ↑
          read total   write total (lifetime)

cAdvisor per-second rates:
  Read:  45 MB/s, 3,200 IOPS
  Write: 12 MB/s,   800 IOPS
  
  Disk write IOPS 800 → within SSD limits ✅
```

**When to use**:
- Database container I/O tuning
- Detecting containers saturating shared host disk bandwidth
- Docker volume vs tmpfs performance comparison

---

### 15.5 Container Restart Count & Uptime

**Definition**: How many times a container has restarted and how long it has been running.

**Formula**:
```
Restart Rate = Total Restarts / Observation Period
Uptime (%) = (Container Up Time / Total Observation Time) × 100
```

**Docker Inspect Fields**:
```bash
docker inspect <container> | jq '.[0].RestartCount'
docker inspect <container> | jq '.[0].State.StartedAt'
docker inspect <container> | jq '.[0].State.Status'
```

**Example**:
```
Container: payment-service
  RestartCount: 7 (in last 2 hours)
  Status: restarting
  ExitCode: 137  → OOMKilled (signal 9)

Action: Increase memory limit or fix memory leak

Restart Policies:
  no           → Never restart (dev)
  always       → Always restart
  on-failure   → Restart only on non-zero exit
  unless-stopped → Restart unless manually stopped
```

**When to use**:
- Health monitoring of production Docker Compose stacks
- Alerting on crash-looping containers (restart count > N in time window)
- Distinguishing graceful restarts from crash loops

---

### 15.6 Container Image & Layer Metrics

**Definition**: Size and efficiency metrics for Docker images used in deployments.

**Key Metrics**:
| Metric | Command | Target |
|---|---|---|
| Image Size (compressed) | `docker images` SIZE column | < 500MB ideally |
| Image Size (uncompressed) | `docker image inspect` | — |
| Layer Count | `docker history <image>` | < 20 layers |
| Image Pull Time | Registry pull duration | < 30s on cold start |
| Image Vulnerability Count | `docker scout cves` / Trivy | 0 Critical/High |
| Image Age | Days since last build | < 30 days (security) |

**Formula**:
```
Image Bloat Ratio = Uncompressed Size / Compressed Size
Ideal ratio ≈ 2–3×
High ratio (>5×) suggests inefficient layer ordering
```

**Example**:
```
docker images:
  REPOSITORY   TAG     IMAGE ID   SIZE
  api-svc      latest  a1b2c3d4   1.23GB  ← Too large!
  api-svc      slim    e5f6g7h8   187MB   ← Good (multi-stage build)

Trivy scan:
  Total: 3 CRITICAL, 12 HIGH → Must fix before deploy
```

**When to use**:
- CI/CD image build optimization
- Security scanning gates before registry push
- Startup time optimization for auto-scaling containers

---

### 15.7 Docker Host Metrics

**Definition**: Resource usage at the Docker daemon and host level.

**Key Metrics**:
| Metric | Command | Target |
|---|---|---|
| Running Containers | `docker ps \| wc -l` | Monitor capacity |
| Total Images | `docker images \| wc -l` | Clean up unused |
| Disk Used by Docker | `docker system df` | < 70% of disk |
| Dangling Images | `docker images -f dangling=true` | Should be 0 |
| Unused Volumes | `docker volume ls -f dangling=true` | Clean up regularly |
| Docker Daemon CPU | Host-level monitoring | < 5% overhead |

**Example**:
```bash
docker system df
TYPE            TOTAL   ACTIVE   SIZE      RECLAIMABLE
Images          47      12       18.5GB    14.2GB (76%)
Containers      15      8        2.3GB     1.1GB (47%)
Local Volumes   23      9        8.7GB     5.2GB (59%)
Build Cache     —       —        4.1GB     4.1GB

Action: docker system prune -a → Recover ~19.5GB
```

**When to use**:
- Docker host disk space management
- CI/CD runner maintenance and cleanup jobs
- Detecting image cache bloat on build servers

---

## 16. Kubernetes Deep-Dive Metrics

> Deep Kubernetes metrics go far beyond basic pod CPU/memory. These cover control plane health, scheduler performance, networking (CNI), storage (CSI), etcd, and workload-level metrics.

---

### 16.1 Control Plane Metrics

#### 16.1.1 API Server Metrics

**Key Metrics**:
| Metric | Prometheus Name | Description | Target |
|---|---|---|---|
| API Request Rate | `apiserver_request_total` | Requests/sec by verb/resource | Baseline |
| API Request Latency (p99) | `apiserver_request_duration_seconds` | p99 latency per API call | < 1s for reads, < 4s for writes |
| API Error Rate | `apiserver_request_total{code=~"5.."}` | 5xx server errors | < 0.1% |
| Active Long-Running Requests | `apiserver_longrunning_requests` | WATCH/EXEC requests in flight | Monitor |
| Inflight Requests | `apiserver_current_inflight_requests` | Pending requests per priority | < max inflight limit |
| etcd Request Duration | `etcd_request_duration_seconds` | Time API server spends on etcd calls | < 25ms p99 |

**Formula**:
```
API Error Rate (%) = 
  rate(apiserver_request_total{code=~"5.."}[5m])
  /
  rate(apiserver_request_total[5m]) × 100

API Latency SLO (Google): 
  99th percentile < 1 second for all read operations
  99th percentile < 4 seconds for all mutating operations
```

**Example (PromQL)**:
```promql
# API server error rate
sum(rate(apiserver_request_total{code=~"5.."}[5m])) by (verb)
/
sum(rate(apiserver_request_total[5m])) by (verb)

# Result:
GET:    0.003%  ✅
PATCH:  0.12%   ⚠️  Investigate!
DELETE: 0.0%   ✅
```

**When to use**:
- Diagnosing kubectl command slowness
- Detecting API server overload (too many controllers)
- SLO tracking for Kubernetes control plane

---

#### 16.1.2 etcd Metrics

**Definition**: etcd is the distributed key-value store backing all Kubernetes state. Its health is critical.

**Key Metrics**:
| Metric | Prometheus Name | Target |
|---|---|---|
| DB Size | `etcd_mvcc_db_total_size_in_bytes` | < 2 GB (soft), < 8 GB (hard quota) |
| Leader Changes | `etcd_server_leader_changes_seen_total` | < 3 per hour |
| Proposal Commit Rate | `etcd_server_proposals_committed_total` | Should match applied rate |
| Proposal Failure Rate | `etcd_server_proposals_failed_total` | Should be 0 |
| WAL Sync Duration (p99) | `etcd_disk_wal_fsync_duration_seconds` | < 10ms |
| Backend Commit Duration | `etcd_disk_backend_commit_duration_seconds` | < 25ms |
| Peer Round-Trip Time | `etcd_network_peer_round_trip_time_seconds` | < 50ms |
| Compaction Duration | `etcd_debugging_mvcc_db_compaction_pause_duration` | < 1s |

**Formula**:
```
Proposal Failure Rate = 
  rate(etcd_server_proposals_failed_total[5m])

Any failure rate > 0 = cluster instability (network partition or leader election)

DB Fragmentation Ratio = 
  etcd_mvcc_db_total_size_in_bytes / etcd_mvcc_db_total_size_in_use_in_bytes

Ratio > 2.0 → Run defragmentation: etcdctl defrag
```

**Example**:
```
etcd metrics:
  DB size:             1.8 GB   ← Approaching 2GB soft limit
  Leader changes/hr:   8        ← CRITICAL! Network instability
  WAL fsync p99:       45ms     ← Too slow, check disk (use NVMe for etcd)
  Peer RTT:            120ms    ← Nodes too far apart geographically

Action: Move etcd to dedicated NVMe SSDs, reduce cross-region latency
```

**When to use**:
- Diagnosing mysterious pod scheduling delays
- Pre-upgrade etcd health validation
- etcd backup and compaction scheduling

---

#### 16.1.3 Scheduler Metrics

**Key Metrics**:
| Metric | Description | Target |
|---|---|---|
| Scheduling Latency (p99) | `scheduler_pod_scheduling_duration_seconds` | < 1s |
| Scheduling Attempts | `scheduler_scheduling_attempt_duration_seconds` | Baseline |
| Pending Pods | `scheduler_pending_pods` by queue | Should drain quickly |
| Preemption Events | `scheduler_preemptions_victims` | Alert if frequent |
| Schedule Failures | `scheduler_schedule_attempts_total{result="error"}` | Should be 0 |
| Unschedulable Pods | `kube_pod_status_unschedulable` | Must be 0 |

**Formula**:
```
Scheduling Success Rate (%) = 
  schedule_attempts{result="scheduled"}
  / schedule_attempts_total × 100

Pending Queue Drain Time = 
  pending_pods / (scheduling_rate × success_rate)
```

**When to use**:
- Diagnosing "Pending" pods that never get scheduled
- Detecting cluster autoscaler delays
- Evaluating scheduling plugin (affinity/taint/toleration) performance

---

#### 16.1.4 Controller Manager Metrics

**Key Metrics**:
| Metric | Description | Target |
|---|---|---|
| Work Queue Depth | `workqueue_depth` by controller | Should be near 0 |
| Reconciliation Duration | `workqueue_queue_duration_seconds` | < 1s |
| Work Queue Add Rate | `workqueue_adds_total` rate | Monitor for spikes |
| Reconciliation Errors | `workqueue_retries_total` | Should be low |

**When to use**:
- Diagnosing slow Deployment rollouts
- Detecting controllers falling behind on reconciliation
- Custom controller / operator performance tuning

---

### 16.2 Node-Level Kubernetes Metrics

**Key Metrics**:
| Metric | PromQL | Target |
|---|---|---|
| Node CPU Allocatable Used % | `sum(kube_pod_container_resource_requests{resource="cpu",node="X"}) / kube_node_status_allocatable{resource="cpu",node="X"}` | < 80% |
| Node Memory Allocatable Used % | Same pattern for memory | < 80% |
| Node Condition | `kube_node_status_condition{condition="Ready",status="true"}` | Must be 1 |
| Node NotReady Count | `count(kube_node_status_condition{condition="Ready",status!="true"})` | Must be 0 |
| Node Disk Pressure | `kube_node_status_condition{condition="DiskPressure",status="true"}` | Must be 0 |
| Node Memory Pressure | `kube_node_status_condition{condition="MemoryPressure",status="true"}` | Must be 0 |
| Node PID Pressure | `kube_node_status_condition{condition="PIDPressure",status="true"}` | Must be 0 |
| Kubelet Eviction Events | `kubelet_evictions_total` | Alert on any |

**Node Allocatable vs Capacity**:
```
Capacity     = Total physical resources on node
Allocatable  = Capacity − system-reserved − kube-reserved − eviction-threshold

Example (8-core node):
  Capacity:    8 cores
  kube-reserved: 0.5 cores
  system-reserved: 0.3 cores
  eviction-threshold: 0.1 cores
  Allocatable: 7.1 cores

Pods can only request up to 7.1 cores on this node
```

**When to use**:
- Cluster capacity planning and node bin-packing
- Detecting node pressure conditions that trigger evictions
- Kubernetes Cluster Autoscaler scaling decisions

---

### 16.3 Pod & Workload Metrics

**Comprehensive Pod Health Metrics**:
| Metric | PromQL | Normal |
|---|---|---|
| Pod Phase Distribution | `kube_pod_status_phase` | All pods Running/Succeeded |
| Container Ready % | `kube_pod_container_status_ready` | 100% |
| Restart Count (rolling 1h) | `increase(kube_pod_container_status_restarts_total[1h])` | < 3 per pod |
| OOMKill Events | `kube_pod_container_status_last_terminated_reason{reason="OOMKilled"}` | 0 |
| Crash Loop Detection | `kube_pod_container_status_waiting_reason{reason="CrashLoopBackOff"}` | 0 |
| Evicted Pods | `kube_pod_status_reason{reason="Evicted"}` | 0 |
| Pod Startup Latency | `pod_start_slo_duration_seconds` | < 5s (kubelet SLO) |

**Deployment Health Metrics**:
| Metric | Description | Target |
|---|---|---|
| Desired Replicas | `kube_deployment_spec_replicas` | — |
| Available Replicas | `kube_deployment_status_replicas_available` | == Desired |
| Updated Replicas | `kube_deployment_status_replicas_updated` | == Desired (post-rollout) |
| Rollout Progress | Available / Desired × 100 | 100% in steady state |

**Formula**:
```
Deployment Health (%) = 
  kube_deployment_status_replicas_available
  / kube_deployment_spec_replicas × 100

< 100% = Degraded deployment (investigate)
= 0%   = Deployment completely down (incident!)
```

**HPA (Horizontal Pod Autoscaler) Metrics**:
```
HPA Desired Replicas = ceil(currentReplicas × (currentMetricValue / desiredMetricValue))

Example:
  Current pods:       5
  Current CPU avg:    80%
  Target CPU:         50%
  Desired = ceil(5 × (80/50)) = ceil(8) = 8 pods → Scale up to 8

HPA Metrics:
  kube_horizontalpodautoscaler_status_current_replicas
  kube_horizontalpodautoscaler_status_desired_replicas
  kube_horizontalpodautoscaler_spec_max_replicas
```

**When to use**:
- Production deployment health dashboards
- Incident triage (which pods are down and why)
- HPA scaling behavior analysis

---

### 16.4 Kubernetes Networking Metrics (CNI)

**Definition**: Network performance within the Kubernetes cluster (pod-to-pod, pod-to-service, ingress).

**Key Metrics**:
| Metric | Tool | Description | Target |
|---|---|---|---|
| Pod-to-Pod Latency | Cilium / Calico metrics | Round-trip time between pods | < 1ms intra-node, < 5ms cross-node |
| Service Endpoint Hit Rate | `kube_endpoint_address_available` | Available endpoints / total | 100% |
| kube-proxy Rules | `kubeproxy_sync_proxy_rules_duration_seconds` | Time to sync iptables/IPVS | < 1s |
| DNS Lookup Latency | CoreDNS `coredns_dns_request_duration_seconds` | p99 DNS resolution time | < 5ms |
| DNS Error Rate | `coredns_dns_responses_total{rcode="SERVFAIL"}` | DNS failures | 0 |
| Ingress Error Rate | Nginx Ingress `nginx_ingress_controller_requests` | 5xx from ingress | < 0.1% |
| Network Policy Drops | Cilium `cilium_drop_count_total` | Packets dropped by policy | Alert on unexpected |

**CoreDNS Performance**:
```
DNS Request Rate = rate(coredns_dns_requests_total[5m])
DNS Error Rate   = rate(coredns_dns_responses_total{rcode!="NOERROR"}[5m])
                   / rate(coredns_dns_requests_total[5m]) × 100

Typical target: < 0.01% DNS error rate
High DNS errors → pods cannot resolve service names → cascading failures
```

**Example (CoreDNS alert)**:
```
coredns_dns_request_duration_seconds_p99 = 450ms  ← Too slow!

Common causes:
  - CoreDNS pods resource-starved (increase CPU requests)
  - ndots:5 default causing excessive DNS lookups (reduce to ndots:2)
  - CoreDNS cache miss rate too high (increase cache TTL)
```

**When to use**:
- Diagnosing service discovery failures
- Debugging slow microservice calls (could be DNS)
- CNI plugin comparison (Calico vs Cilium vs Flannel)

---

### 16.5 Kubernetes Storage Metrics (CSI / PVC)

**Key Metrics**:
| Metric | Prometheus Name | Target |
|---|---|---|
| PVC Usage % | `kubelet_volume_stats_used_bytes / kubelet_volume_stats_capacity_bytes` | < 80% |
| PVC Inode Usage % | `kubelet_volume_stats_inodes_used / kubelet_volume_stats_inodes` | < 80% |
| Volume Mount Errors | `storage_operation_errors_total` | 0 |
| CSI Operation Latency | `storage_operation_duration_seconds` | < 5s for attach/detach |
| PV Reclaim Duration | Time from PVC delete to PV available | < 30s |
| Unbound PVCs | `kube_persistentvolumeclaim_status_phase{phase!="Bound"}` | 0 |

**Formula**:
```
PVC Utilization (%) = 
  kubelet_volume_stats_used_bytes
  / kubelet_volume_stats_capacity_bytes × 100

Inode Utilization (%) =
  kubelet_volume_stats_inodes_used
  / kubelet_volume_stats_inodes × 100

Both must be < 80% to avoid disk full errors
(Volume can run out of inodes before bytes!)
```

**Example**:
```
PVC: postgres-data
  Capacity:  100Gi
  Used:       87Gi  → 87% — ALERT!
  Inodes:    6,553,600
  Inodes used: 4,200,000 → 64% — OK

Action: Expand PVC or archive old data immediately
```

**When to use**:
- Database PVC capacity planning
- Pre-emptive storage expansion alerts
- StorageClass performance benchmarking

---

### 16.6 Kubernetes Resource Quota & LimitRange

**Key Metrics**:
| Metric | PromQL | Target |
|---|---|---|
| Namespace CPU Used / Quota | `kube_resourcequota{resource="requests.cpu",type="used"} / kube_resourcequota{resource="requests.cpu",type="hard"}` | < 80% |
| Namespace Memory Used / Quota | Same pattern for memory | < 80% |
| Namespace Pod Count / Limit | `kube_resourcequota{resource="pods",type="used"} / kube_resourcequota{resource="pods",type="hard"}` | < 90% |
| Namespace Object Count | `kube_resourcequota{resource="count/deployments.apps",type="used"}` | Monitor |

**Formula**:
```
Quota Utilization (%) = used_quantity / hard_limit × 100

Example namespace "payments":
  CPU Requests used:    18 cores / 20 cores = 90% ← Nearly exhausted!
  Memory Requests used: 48 GiB / 64 GiB     = 75% ← OK
  Pod count:            92 / 100             = 92% ← Near limit

Action: Request quota increase or reduce over-provisioned requests
```

**When to use**:
- Multi-tenant cluster resource governance
- Namespace-level chargeback and showback
- Detecting quota exhaustion before deployments fail

---

### 16.7 Kubernetes Cost Metrics (Kubecost / OpenCost)

**Key Metrics**:
| Metric | Description | Formula |
|---|---|---|
| Pod Cost / Hour | Cost of running a pod | (CPU cost × CPU request) + (Mem cost × Mem request) |
| Namespace Cost | Aggregated pod costs in namespace | Sum of all pod costs |
| Efficiency Score | Actual usage / Requested resources | Usage / Request × 100 |
| Idle Cost | Cost of requested but unused resources | (Request − Usage) × Resource Price |
| Cost per Team | Cost allocated by label/team | Sum by `team` label |

**Formula (Pod Cost)**:
```
Pod Cost/hr = 
  (CPU_request_cores × CPU_cost_per_core_hr)
  + (Memory_request_GiB × Memory_cost_per_GiB_hr)
  + (GPU_request × GPU_cost_per_hr)

Example (AWS us-east-1, m5.xlarge):
  CPU cost/core/hr:  $0.048
  Memory cost/GiB/hr: $0.006

  Pod with 2 CPU, 4 GiB:
  Pod Cost/hr = (2 × $0.048) + (4 × $0.006) = $0.096 + $0.024 = $0.12/hr
  Pod Cost/month = $0.12 × 730 = $87.60/month
```

**Efficiency Score**:
```
CPU Efficiency = avg(rate(container_cpu_usage_seconds_total[1h])) / sum(kube_pod_container_resource_requests{resource="cpu"})

Memory Efficiency = avg(container_memory_working_set_bytes) / sum(kube_pod_container_resource_requests{resource="memory"})

Target: > 65% efficiency (< 65% = significant waste)
```

**When to use**:
- Engineering team cost accountability
- FinOps optimization — identifying wasteful workloads
- Kubernetes request/limit rightsizing

---

## 17. Cloud Platform Metrics (AWS / GCP / Azure)

> Each major cloud provider exposes hundreds of metrics via their native monitoring services. Below are the most critical metrics for each platform organized by service category.

---

### 17.1 AWS Metrics (CloudWatch)

#### 17.1.1 AWS EC2 Metrics

**Key Metrics**:
| Metric | Namespace | Description | Threshold |
|---|---|---|---|
| `CPUUtilization` | AWS/EC2 | CPU % | Alert > 85% |
| `CPUCreditBalance` | AWS/EC2 | T-series burst credits remaining | Alert < 20 |
| `CPUCreditUsage` | AWS/EC2 | Credits consumed/min | Monitor |
| `NetworkIn` / `NetworkOut` | AWS/EC2 | Bytes in/out | Baseline |
| `DiskReadOps` / `DiskWriteOps` | AWS/EC2 | IOPS (instance store only) | Baseline |
| `StatusCheckFailed` | AWS/EC2 | Instance/system status check | Must be 0 |
| `StatusCheckFailed_Instance` | AWS/EC2 | Guest OS failure | Must be 0 |
| `StatusCheckFailed_System` | AWS/EC2 | AWS hardware failure | Must be 0 |
| `MetadataNoToken` | AWS/EC2 | IMDSv1 usage (security risk) | Should be 0 |

**CPU Credit Formula (Burstable Instances)**:
```
Credit Balance = Previous Balance + Credits Earned − Credits Spent

Credit Earn Rate (t3.medium):
  vCPUs: 2
  Baseline: 20% CPU
  Credits earned/hr: 2 vCPUs × 20 credits = 40 credits/hr
  Max balance: 576 credits

Credit Spend Rate:
  At 100% CPU: 2 credits/minute = 120 credits/hr
  At 20% CPU:  0 net (earning = spending)
  At 5% CPU:   accumulating credits

When Balance = 0:
  Standard mode (t3): Throttled to 20% baseline
  Unlimited mode:     Continues at cost (cpu_credits charge)
```

**When to use**:
- Right-sizing EC2 instance types
- Detecting burstable instance credit starvation
- EC2 hardware failure alerting

---

#### 17.1.2 AWS RDS Metrics

**Key Metrics**:
| Metric | Description | Target |
|---|---|---|
| `CPUUtilization` | RDS instance CPU | < 80% |
| `DatabaseConnections` | Active DB connections | < max_connections × 0.8 |
| `FreeStorageSpace` | Free disk space (bytes) | Alert < 20% remaining |
| `FreeableMemory` | Available RAM | Alert < 20% |
| `ReadIOPS` / `WriteIOPS` | Disk IOPS | < provisioned IOPS |
| `ReadLatency` / `WriteLatency` | I/O latency in seconds | < 10ms |
| `ReadThroughput` / `WriteThroughput` | MB/s | < provisioned throughput |
| `ReplicaLag` | Read replica replication lag (sec) | < 1s |
| `BurstBalance` | gp2 burst credits remaining | Alert < 20% |
| `DiskQueueDepth` | Pending I/O operations | < 1 |

**Formula**:
```
Storage Used % = (AllocatedStorage − FreeStorageSpace) / AllocatedStorage × 100

Example:
  AllocatedStorage: 500 GB = 536,870,912,000 bytes
  FreeStorageSpace:  80 GB =  85,899,345,920 bytes

  Used = (500 − 80) / 500 × 100 = 84% ← Alert!
```

**gp2 Burst IOPS**:
```
gp2 Baseline IOPS = Volume Size (GB) × 3
  (min 100 IOPS, max 3,000 IOPS for < 1TB)

gp2 Burst IOPS = 3,000 IOPS (for volumes < 1TB)
Burst depletes bucket when usage > baseline
Bucket Credits = VolumeSize × 5,400,000 I/O credits

Recommendation: Migrate to gp3 for consistent IOPS without credits
```

**When to use**:
- RDS right-sizing and storage auto-scaling configuration
- Read replica lag monitoring for application consistency
- Proactive storage expansion before alerts

---

#### 17.1.3 AWS ELB / ALB Metrics

**Key Metrics**:
| Metric | Description | Target |
|---|---|---|
| `RequestCount` | Total requests to load balancer | Baseline |
| `TargetResponseTime` | Backend response time | < 500ms p99 |
| `HTTPCode_Target_5XX_Count` | Backend 5xx errors | < 0.1% of requests |
| `HTTPCode_ELB_5XX_Count` | ELB-generated 5xx | Must be 0 |
| `HealthyHostCount` | Healthy targets in target group | Must equal desired |
| `UnHealthyHostCount` | Unhealthy targets | Must be 0 |
| `RejectedConnectionCount` | Connections rejected (surge queue full) | Must be 0 |
| `ActiveConnectionCount` | Active TCP connections | Monitor capacity |
| `ConsumedLCUs` | Load balancer capacity units (billing) | Monitor cost |

**Formula**:
```
ALB Error Rate (%) = 
  HTTPCode_Target_5XX_Count / RequestCount × 100

LCU Calculation (billing):
  LCUs = max(
    New connections/sec / 25,
    Active connections / 3,000,
    Processed bytes (GB/hr) / 1,
    Rule evaluations/sec / 1,000
  )
  Cost = LCUs × $0.008/hr
```

**When to use**:
- ALB health and capacity monitoring
- Target group health check tuning
- ALB cost optimization (reduce unnecessary rule evaluations)

---

#### 17.1.4 AWS Lambda Metrics

**Key Metrics**:
| Metric | Description | Target |
|---|---|---|
| `Invocations` | Total function calls | Baseline |
| `Duration` | Execution time (ms) | < configured timeout |
| `Errors` | Function errors | < 0.1% |
| `Throttles` | Rate-limited invocations | Must be 0 |
| `ConcurrentExecutions` | Simultaneous executions | < account limit |
| `UnreservedConcurrentExecutions` | Shared pool usage | Monitor |
| `InitDuration` | Cold start initialization time | < 1s |
| `IteratorAge` | For stream triggers: message age | < SLA |
| `DeadLetterErrors` | Failed DLQ deliveries | Must be 0 |

**Cold Start Formula**:
```
Cold Start Rate (%) = 
  Invocations with Init Duration / Total Invocations × 100

Cold Start Impact:
  Total Duration = Init Duration + Execution Duration
  
  Python Lambda: Init ~200ms + Execution 50ms = 250ms total
  Java Lambda:   Init ~2000ms + Execution 50ms = 2050ms total ← Significant!

Mitigation: Provisioned Concurrency, SnapStart (Java 21+)
```

**Throttle Rate Formula**:
```
Throttle Rate (%) = Throttles / (Invocations + Throttles) × 100

If throttle rate > 0%:
  - Request concurrency limit increase, OR
  - Implement exponential backoff in caller
```

**When to use**:
- Serverless application performance monitoring
- Cold start optimization analysis
- Lambda concurrency limit planning

---

#### 17.1.5 AWS S3 Metrics

**Key Metrics**:
| Metric | Description | Target |
|---|---|---|
| `NumberOfObjects` | Total objects in bucket | Monitor growth |
| `BucketSizeBytes` | Total storage used | Monitor vs cost |
| `AllRequests` | Total S3 API requests | Baseline |
| `GetRequests` / `PutRequests` | Read/write operations | Baseline |
| `4xxErrors` / `5xxErrors` | Error rates | < 0.1% |
| `FirstByteLatency` | Time to first byte | < 200ms p99 |
| `TotalRequestLatency` | Full request duration | < 500ms p99 |
| `BytesDownloaded` / `BytesUploaded` | Data transfer | Monitor egress cost |

**Cost Formula**:
```
S3 Monthly Storage Cost = 
  BucketSizeBytes / 1,073,741,824 (GiB) × $0.023 (Standard)

S3 Request Cost:
  PUT/COPY/POST: $0.005 per 1,000
  GET:           $0.0004 per 1,000

Egress Cost:
  Data out to internet: $0.09/GB (first 10TB)
  Data to CloudFront:   $0.00/GB (free)

Optimization: Serve from CloudFront instead of S3 directly
```

**When to use**:
- S3 cost management and lifecycle policy tuning
- CDN cache hit rate vs S3 origin request ratio
- S3 error rate monitoring for application dependencies

---

#### 17.1.6 AWS EKS-Specific Metrics

**Key Metrics**:
| Metric | Source | Description | Target |
|---|---|---|---|
| Node Group Scaling Activity | CloudWatch | Scale-out/in events | Monitor convergence time |
| Cluster Autoscaler Decisions | CA logs/metrics | Scale-up vs scale-down | < 3 min to scale out |
| EKS Control Plane API Latency | CloudWatch | Managed API server p99 | < 1s |
| VPC CNI IPAMD Available IPs | `awscni_assigned_ip_addresses` | Available IPs per node | Alert < 5 IPs |
| ENI Usage | `awscni_eni_allocated` | ENIs attached per node | < max ENIs for instance type |

**VPC CNI IP Exhaustion**:
```
Max Pods per Node = (ENIs per instance − 1) × (IPs per ENI − 1) + 2

Example m5.large:
  Max ENIs: 3
  IPs per ENI: 10
  Max Pods = (3−1) × (10−1) + 2 = 2×9+2 = 20 pods

If pods > 20 → Pods stay Pending (IP exhaustion)
Fix: Use prefix delegation or switch to VPC-native CNI
```

---

### 17.2 GCP Metrics (Cloud Monitoring)

#### 17.2.1 GCP Compute Engine Metrics

**Key Metrics**:
| Metric | Full Name | Description | Target |
|---|---|---|---|
| CPU Utilization | `compute.googleapis.com/instance/cpu/utilization` | CPU % | < 0.85 |
| Disk Read/Write Ops | `compute.googleapis.com/instance/disk/read_ops_count` | IOPS | < provisioned |
| Network Bytes In/Out | `compute.googleapis.com/instance/network/received_bytes_count` | Bytes/sec | Baseline |
| Uptime Check | `monitoring.googleapis.com/uptime_check/check_passed` | Health check pass | Must be 1 |
| Guest Memory Used | `agent.googleapis.com/memory/bytes_used` | RAM (requires agent) | < 80% |
| Sustained Use Discount | Billing metric | Automatic discount on sustained usage | Track savings |

**Committed Use Discount (CUD) Efficiency**:
```
CUD Efficiency (%) = 
  Hours committed resource was used / Total committed hours × 100

If < 70% → Commitment is being wasted
If > 90% → May need more commitment

CUD saves up to 57% vs on-demand for compute-optimized
```

---

#### 17.2.2 GCP GKE Metrics

**Key Metrics**:
| Metric | Description | Target |
|---|---|---|
| `kubernetes.io/container/cpu/request_utilization` | CPU actual vs request | < 80% |
| `kubernetes.io/container/memory/request_utilization` | Memory actual vs request | < 80% |
| `kubernetes.io/node/cpu/allocatable_utilization` | Node allocatable CPU used | < 80% |
| `kubernetes.io/pod/volume/used_bytes` | PVC usage | < 80% of capacity |
| Cluster Autoscaler Scale-Up Latency | Time to ready new node | < 3 minutes |
| Node Auto-Provisioning (NAP) | Nodes created for unschedulable pods | Monitor convergence |

**GKE Autopilot Cost Model**:
```
Autopilot charges per Pod resources (not nodes):
  CPU:    $0.0445/vCPU/hr
  Memory: $0.00490/GiB/hr
  Storage: $0.000048/GiB/hr

Pod Cost/hr = (requested_cpu × $0.0445) + (requested_memory_GiB × $0.0049)

Minimum: 250m CPU, 512MiB memory per pod
```

---

#### 17.2.3 GCP Cloud SQL Metrics

**Key Metrics**:
| Metric | Description | Target |
|---|---|---|
| `cloudsql.googleapis.com/database/cpu/utilization` | CPU usage | < 0.8 |
| `cloudsql.googleapis.com/database/memory/utilization` | Memory usage | < 0.8 |
| `cloudsql.googleapis.com/database/disk/utilization` | Disk usage | < 0.8 |
| `cloudsql.googleapis.com/database/network/connections` | Active connections | < max_connections × 0.8 |
| `cloudsql.googleapis.com/database/replication/replica_lag` | HA replica lag | < 1s |
| `cloudsql.googleapis.com/database/auto_failover_request_count` | HA failover events | Alert on any |

---

#### 17.2.4 GCP Cloud Run Metrics

**Key Metrics**:
| Metric | Description | Target |
|---|---|---|
| `run.googleapis.com/request_count` | Total requests | Baseline |
| `run.googleapis.com/request_latencies` | Request duration | < 500ms p99 |
| `run.googleapis.com/container/instance_count` | Running instances | Monitor scaling |
| `run.googleapis.com/container/cpu/utilizations` | CPU per instance | < 0.8 |
| `run.googleapis.com/container/memory/utilizations` | Memory per instance | < 0.8 |
| Cold Start Frequency | Requests hitting new instances | Minimize with min-instances |

**Concurrency & Auto-scaling**:
```
Cloud Run scales based on:
  Target Concurrency: requests per instance before scaling
  
  Desired instances = ceil(Total RPS / (Target Concurrency × Max CPU))
  
Example:
  Total RPS: 1,000
  Target Concurrency: 80 requests/instance
  Desired instances = ceil(1,000 / 80) = 13 instances

Cost = instances × vCPU × $0.00002400/vCPU-second
       + instances × memory × $0.00000250/GiB-second
```

---

### 17.3 Azure Metrics (Azure Monitor)

#### 17.3.1 Azure Virtual Machines

**Key Metrics**:
| Metric | Description | Target |
|---|---|---|
| `Percentage CPU` | CPU utilization | < 85% |
| `Available Memory Bytes` | Free RAM | Alert < 20% |
| `Disk Read/Write Bytes` | I/O throughput | < provisioned |
| `Disk Read/Write Operations/Sec` | IOPS | < provisioned |
| `Network In/Out Total` | Network bytes | Baseline |
| `VM Availability` | Azure platform health | Must be 100% |
| `OS Disk IOPS Consumed %` | Disk IOPS vs limit | < 80% |
| `Data Disk IOPS Consumed %` | Per-disk IOPS | < 80% |

**Azure Spot/Burstable VM Metrics**:
```
Bv2 (Burstable) Credit Balance:
  B1s:  Earns 6 credits/hr, max 144 credits
  B2s:  Earns 12 credits/hr, max 288 credits
  100% CPU burns 1 credit/minute

Spot VM Eviction Rate:
  Monitor: 'Eviction Rate' in Azure Monitor
  Alert: When spot price > your max price bid
```

---

#### 17.3.2 Azure AKS Metrics

**Key Metrics**:
| Metric | Namespace | Description | Target |
|---|---|---|---|
| `node_cpu_usage_percentage` | Insights | Node CPU % | < 80% |
| `node_memory_rss_percentage` | Insights | Node memory % | < 80% |
| `node_disk_usage_percentage` | Insights | Node disk % | < 80% |
| `pod_count` | Insights | Running pods | Monitor capacity |
| `kube_node_status_condition` | kube-state-metrics | Node health | All Ready |
| VMSS Scale Events | Azure Monitor | Node pool autoscale | Monitor convergence |
| `container_cpu_usage_seconds_total` | cAdvisor | Container CPU | Monitor throttle |

**AKS Node Pool Autoscaler**:
```
Scale-Out Trigger:
  Pending pods that cannot be scheduled → trigger scale-out
  New node provisioning time: 2–5 minutes (Azure VMSS)

Scale-In Rules:
  Node utilization < 50% for > 10 minutes → candidate for removal
  Scale-in blocked if: pod without disruption budget, local storage, etc.

Key metric to alert:
  time_to_first_pod_scheduled > 5 minutes → Autoscaler too slow
```

---

#### 17.3.3 Azure SQL / Cosmos DB Metrics

**Azure SQL Key Metrics**:
| Metric | Description | Target |
|---|---|---|
| `cpu_percent` | DTU/vCore CPU usage | < 80% |
| `dtu_consumption_percent` | DTU utilization (DTU tier) | < 80% |
| `storage_percent` | Storage used % | < 80% |
| `connection_successful` | Successful DB connections | Monitor |
| `connection_failed` | Failed connections | Alert > 0 |
| `deadlock` | Deadlock events | Alert > 0 |
| `workers_percent` | Max worker threads used | < 80% |

**Cosmos DB Key Metrics**:
| Metric | Description | Target |
|---|---|---|
| `TotalRequests` | Requests per second | Baseline |
| `NormalizedRUConsumption` | RU/s usage % of provisioned | < 80% |
| `RequestCharge` | RUs consumed per request | Optimize queries |
| `ServiceAvailability` | Cosmos DB SLA | ≥ 99.999% (multi-region) |
| `ServerSideLatency` | Server processing time | < 10ms for point reads |
| `TotalRequestUnits` | Total RU/s consumed | Compare vs provisioned |

**RU (Request Unit) Formula**:
```
RU Cost varies by operation:
  Point Read (1KB doc):    1 RU
  Write (1KB doc):         ~5 RUs
  Query (returns 100 docs): 10–100 RUs (depends on query efficiency)

Monthly Cost = Provisioned RU/s × 730 hrs × $0.008 per 100 RU/hr

Example:
  10,000 RU/s provisioned:
  Cost = 10,000 / 100 × 730 × $0.008 = $584/month
```

---

#### 17.3.4 Azure Application Gateway / Front Door Metrics

**Key Metrics**:
| Metric | Description | Target |
|---|---|---|
| `TotalRequests` | Total requests handled | Baseline |
| `FailedRequests` | Failed (5xx) requests | < 0.1% |
| `ResponseStatus` | HTTP response code distribution | 2xx should dominate |
| `Throughput` | Bytes/sec processed | < gateway tier limit |
| `CurrentConnections` | Active connections | < max capacity |
| `HealthyHostCount` | Healthy backend servers | = Desired count |
| `UnhealthyHostCount` | Unhealthy backends | Must be 0 |
| `BackendConnectTime` | Time to connect to backend | < 10ms |
| `BackendResponseTime` | Backend server response time | < 200ms p99 |
| `WAF Blocked Requests` | Requests blocked by WAF rules | Monitor for false positives |

---

### 17.4 Multi-Cloud Observability Metrics

**Cross-Cloud Cost Comparison Metrics**:
| Metric | Description | Tool |
|---|---|---|
| Cloud Spend by Service | Cost per AWS/GCP/Azure service | Cost Explorer, Billing Export |
| Waste (Unattached Resources) | Idle EIPs, unattached EBS, etc. | CloudHealth, Infracost |
| Reserved/Committed Usage % | RI/CUD/Savings Plan utilization | Native billing dashboards |
| Egress Cost by Region | Data transfer out costs | Billing APIs |
| Tag Compliance % | Resources with required tags | Config rules |
| Carbon Footprint | CO₂ equivalent emissions | AWS Carbon Footprint Tool |

**Reserved Instance / Savings Plan Efficiency**:
```
RI Utilization (%) = 
  Hours RI was used / Total RI hours × 100

Target: > 80% (below = waste, you're paying for unused capacity)

RI Coverage (%) = 
  On-demand hours covered by RI / Total on-demand hours × 100

Target: > 70% (below = too much on-demand, buy more RIs)

Net Savings = On-Demand Cost − (RI Cost + Unused RI Cost)
```

**Multi-Cloud SLA Comparison**:
| Service Type | AWS SLA | GCP SLA | Azure SLA |
|---|---|---|---|
| Compute (VM) | 99.99% (multi-AZ) | 99.99% (multi-zone) | 99.99% (availability set) |
| Managed K8s | 99.95% (EKS) | 99.95% (GKE) | 99.95% (AKS) |
| Managed DB | 99.95% (RDS Multi-AZ) | 99.95% (Cloud SQL HA) | 99.99% (Azure SQL) |
| Object Storage | 99.99% (S3) | 99.99% (GCS) | 99.99% (Blob) |
| CDN | 99.9% (CloudFront) | 99.9% (Cloud CDN) | 99.99% (Front Door) |

---

### Appendix: Docker Metrics Cheat Sheet

```
Docker:
  Container CPU (%)      = delta_container_cpu / delta_system_cpu × num_cpus × 100
  Container Memory (%)   = working_set / memory_limit × 100
  Working Set            = usage_in_bytes − inactive_file_bytes
  Network RX/TX (MB/s)   = delta_bytes / delta_time / 1,048,576
  Image Bloat Ratio      = Uncompressed Size / Compressed Size
  Throttle Rate (%)      = throttled_time / (throttled + elapsed) × 100
```

### Appendix: Kubernetes Deep-Dive Cheat Sheet

```
Kubernetes:
  API Error Rate (%)     = 5xx requests / total requests × 100
  etcd Fragmentation     = db_total_size / db_in_use_size (target < 2.0)
  Pod Health (%)         = available_replicas / desired_replicas × 100
  HPA Scale Target       = ceil(currentReplicas × (currentMetric / desiredMetric))
  PVC Usage (%)          = used_bytes / capacity_bytes × 100
  Quota Utilization (%)  = used / hard_limit × 100
  Node Allocatable Used  = sum(pod_requests) / node_allocatable × 100
  K8s Cost/Pod/hr        = (CPU_req × cpu_price) + (Mem_req_GiB × mem_price)
```

### Appendix: Cloud Metrics Cheat Sheet

```
AWS:
  EC2 Credit Balance     = Prev Balance + Credits Earned − Credits Spent
  gp2 Baseline IOPS      = Volume Size (GB) × 3
  ALB Error Rate (%)     = 5xx_count / total_requests × 100
  Lambda Cold Start (%)  = init_invocations / total_invocations × 100
  Lambda Throttle (%)    = Throttles / (Invocations + Throttles) × 100
  S3 Storage Cost/mo     = SizeGiB × $0.023

GCP:
  CUD Efficiency (%)     = hours_used / hours_committed × 100
  Cloud Run Instances    = ceil(RPS / target_concurrency)
  GKE Autopilot Cost/hr  = cpu_req × $0.0445 + mem_GiB × $0.0049

Azure:
  Cosmos RU Cost/mo      = provisioned_RU/100 × 730hrs × $0.008
  RI Utilization (%)     = hours_RI_used / total_RI_hours × 100
  RI Coverage (%)        = on_demand_hours_covered / total_on_demand × 100
```

---

*Last Updated: June 2026 | Maintained by DevOps / SRE Team*
