import { runSecurityAnalysis } from "./services/securityEngine";
import { performance } from "perf_hooks";

interface LabeledSample {
  id: number;
  log: string;
  sourceType: "firewall" | "auth" | "web" | "system" | "other";
  isMalicious: boolean;
  expectedThreatType?: string;
  category: string;
}

const BENCHMARK_DATASET: LabeledSample[] = [
  // Malicious samples
  {
    id: 1,
    log: "GET /products?id=1 UNION SELECT username,password FROM users-- HTTP/1.1",
    sourceType: "web",
    isMalicious: true,
    expectedThreatType: "sql_injection",
    category: "SQL Injection",
  },
  {
    id: 2,
    log: "POST /login HTTP/1.1 user=admin' OR '1'='1' -- password=foo",
    sourceType: "web",
    isMalicious: true,
    expectedThreatType: "sql_injection",
    category: "SQL Injection",
  },
  {
    id: 3,
    log: "GET /search?q=<script>alert('XSS')</script> HTTP/1.1",
    sourceType: "web",
    isMalicious: true,
    expectedThreatType: "xss",
    category: "Cross-Site Scripting",
  },
  {
    id: 4,
    log: "POST /comment body=<img src=x onerror=javascript:document.cookie> HTTP/1.1",
    sourceType: "web",
    isMalicious: true,
    expectedThreatType: "xss",
    category: "Cross-Site Scripting",
  },
  {
    id: 5,
    log: "GET /../../../../etc/passwd HTTP/1.1",
    sourceType: "web",
    isMalicious: true,
    expectedThreatType: "path_traversal",
    category: "Path Traversal",
  },
  {
    id: 6,
    log: "GET /static/..%2f..%2fwindows/win.ini HTTP/1.1",
    sourceType: "web",
    isMalicious: true,
    expectedThreatType: "path_traversal",
    category: "Path Traversal",
  },
  {
    id: 7,
    log: "Failed password for root from 192.168.1.105 port 54321 ssh2",
    sourceType: "auth",
    isMalicious: true,
    expectedThreatType: "brute_force",
    category: "Brute Force",
  },
  {
    id: 8,
    log: "Failed password for admin from 192.168.1.105 port 54322 ssh2",
    sourceType: "auth",
    isMalicious: true,
    expectedThreatType: "brute_force",
    category: "Brute Force",
  },
  {
    id: 9,
    log: "powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA== -nop -w hidden",
    sourceType: "system",
    isMalicious: true,
    expectedThreatType: "malware",
    category: "Malware / Execution",
  },
  {
    id: 10,
    log: "TCP SYN port scan detected from 198.51.100.42 to ports 21,22,23,25,80,443,3389,8080",
    sourceType: "firewall",
    isMalicious: true,
    expectedThreatType: "port_scan",
    category: "Port Scanning",
  },
  {
    id: 11,
    log: "GET /admin/dashboard?id=1; WAITFOR DELAY '0:0:5'-- HTTP/1.1",
    sourceType: "web",
    isMalicious: true,
    expectedThreatType: "sql_injection",
    category: "SQL Injection",
  },
  {
    id: 12,
    log: "POST /api/upload filename=shell.php.jpg <?php system($_GET['cmd']); ?>",
    sourceType: "web",
    isMalicious: true,
    expectedThreatType: "malware",
    category: "Web Shell",
  },
  {
    id: 13,
    log: "audit: unauthorized access attempt to /etc/shadow by user www-data uid=33",
    sourceType: "system",
    isMalicious: true,
    expectedThreatType: "privilege_escalation",
    category: "Privilege Escalation",
  },
  {
    id: 14,
    log: "Beaconing traffic detected: outbound TCP connection to 185.220.101.5:4444 interval=60s jitter=0.1",
    sourceType: "firewall",
    isMalicious: true,
    expectedThreatType: "malware",
    category: "C2 Beaconing",
  },
  {
    id: 15,
    log: "iptables: DROP TCP flood from 203.0.113.100:12345 -> 10.0.0.1:80 [SYN_FLOOD]",
    sourceType: "firewall",
    isMalicious: true,
    expectedThreatType: "dos",
    category: "Denial of Service",
  },

  // Benign samples
  {
    id: 16,
    log: "GET /index.html HTTP/1.1 200 1024 User-Agent: Mozilla/5.0",
    sourceType: "web",
    isMalicious: false,
    category: "Normal Web Request",
  },
  {
    id: 17,
    log: "GET /assets/style.css HTTP/1.1 200 4523 Cache-Control: max-age=3600",
    sourceType: "web",
    isMalicious: false,
    category: "Static Asset",
  },
  {
    id: 18,
    log: "GET /favicon.ico HTTP/1.1 200 512",
    sourceType: "web",
    isMalicious: false,
    category: "Static Asset",
  },
  {
    id: 19,
    log: "Accepted password for deploy from 10.0.0.12 port 22 ssh2",
    sourceType: "auth",
    isMalicious: false,
    category: "Authorized SSH Login",
  },
  {
    id: 20,
    log: "Accepted publickey for ubuntu from 192.168.1.50 port 55432 ssh2",
    sourceType: "auth",
    isMalicious: false,
    category: "Authorized SSH Login",
  },
  {
    id: 21,
    log: "GET /api/v1/health HTTP/1.1 200 15 status=healthy uptime=86400",
    sourceType: "web",
    isMalicious: false,
    category: "Health Check",
  },
  {
    id: 22,
    log: "POST /api/v1/telemetry HTTP/1.1 204 cpu=12.4 memory=45.1 disk=62.8",
    sourceType: "system",
    isMalicious: false,
    category: "System Telemetry",
  },
  {
    id: 23,
    log: "cron: CRON[9842]: (root) CMD (/usr/local/bin/logrotate /etc/logrotate.conf)",
    sourceType: "system",
    isMalicious: false,
    category: "Routine Cron Job",
  },
  {
    id: 24,
    log: "GET /images/logo.png HTTP/1.1 304 0 If-Modified-Since: Wed, 21 Oct 2025 07:28:00 GMT",
    sourceType: "web",
    isMalicious: false,
    category: "Static Image",
  },
  {
    id: 25,
    log: "kernel: [12345.678] e1000e 0000:00:19.0 eth0: NIC Link is Up 1000 Mbps Full Duplex",
    sourceType: "system",
    isMalicious: false,
    category: "Network Interface State",
  },
  {
    id: 26,
    log: "POST /auth/refresh HTTP/1.1 200 84 user_id=42 session_renewed=true",
    sourceType: "web",
    isMalicious: false,
    category: "Token Refresh",
  },
  {
    id: 27,
    log: "DNS query: A records requested for cdn.cyberguard.internal from 10.0.1.20:53",
    sourceType: "firewall",
    isMalicious: false,
    category: "Internal DNS Query",
  },
  {
    id: 28,
    log: "systemd[1]: Started Daily apt upgrade and clean activities.",
    sourceType: "system",
    isMalicious: false,
    category: "System Maintenance",
  },
  {
    id: 29,
    log: "postfix/smtp[2341]: 8B3C4201A: to=<analyst@cyberguard.ai>, relay=mail.internal:25, status=sent (250 2.0.0 Ok)",
    sourceType: "system",
    isMalicious: false,
    category: "SMTP Delivery",
  },
  {
    id: 30,
    log: "GET /docs/architecture.pdf HTTP/1.1 200 48123 Content-Type: application/pdf",
    sourceType: "web",
    isMalicious: false,
    category: "Document Download",
  },
];

function calculatePercentile(values: number[], percentile: number): number {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = (percentile / 100) * (sorted.length - 1);
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) return sorted[lower];
  return sorted[lower] + (sorted[upper] - sorted[lower]) * (index - lower);
}

async function runBenchmark() {
  console.log("=================================================");
  console.log("   CYBERGUARD AI - COMPREHENSIVE QA & BENCHMARK   ");
  console.log("=================================================\n");

  console.log(`[1] Running AI Threat Detection Benchmark on ${BENCHMARK_DATASET.length} labeled security events...`);

  let tp = 0;
  let tn = 0;
  let fp = 0;
  let fn = 0;

  const latencies: number[] = [];

  for (const sample of BENCHMARK_DATASET) {
    const start = performance.now();
    const result = await runSecurityAnalysis(sample.log);
    const duration = performance.now() - start;
    latencies.push(duration);

    const detected = result.detections.length > 0;

    if (sample.isMalicious && detected) {
      tp++;
    } else if (!sample.isMalicious && !detected) {
      tn++;
    } else if (!sample.isMalicious && detected) {
      fp++;
      console.warn(`[FALSE POSITIVE] ID ${sample.id} (${sample.category}): detected as ${result.detections[0]?.threatType}`);
    } else if (sample.isMalicious && !detected) {
      fn++;
      console.warn(`[FALSE NEGATIVE] ID ${sample.id} (${sample.category}): not detected`);
    }
  }

  const total = BENCHMARK_DATASET.length;
  const accuracy = (tp + tn) / total;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 1;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 1;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;
  const fnr = fn + tp > 0 ? fn / (fn + tp) : 0;

  const avgLatency = latencies.reduce((a, b) => a + b, 0) / latencies.length;
  const p50 = calculatePercentile(latencies, 50);
  const p95 = calculatePercentile(latencies, 95);
  const p99 = calculatePercentile(latencies, 99);
  const maxLatency = Math.max(...latencies);

  console.log("\n--- AI Threat Detection Benchmark Results ---");
  console.log(`Total Samples:       ${total}`);
  console.log(`True Positives (TP): ${tp}`);
  console.log(`True Negatives (TN): ${tn}`);
  console.log(`False Positives (FP):${fp}`);
  console.log(`False Negatives (FN):${fn}`);
  console.log(`Accuracy:            ${(accuracy * 100).toFixed(2)}%`);
  console.log(`Precision:           ${(precision * 100).toFixed(2)}%`);
  console.log(`Recall:              ${(recall * 100).toFixed(2)}%`);
  console.log(`F1-Score:            ${(f1 * 100).toFixed(2)}%`);
  console.log(`False Positive Rate: ${(fpr * 100).toFixed(2)}%`);
  console.log(`False Negative Rate: ${(fnr * 100).toFixed(2)}%`);
  console.log("\n--- AI Inference Latency ---");
  console.log(`Average:             ${avgLatency.toFixed(2)} ms`);
  console.log(`Median (P50):        ${p50.toFixed(2)} ms`);
  console.log(`P95:                 ${p95.toFixed(2)} ms`);
  console.log(`P99:                 ${p99.toFixed(2)} ms`);
  console.log(`Max:                 ${maxLatency.toFixed(2)} ms`);

  // Performance & Concurrency Testing
  console.log("\n[2] Running API Concurrency & Performance Tests (localhost:3000)...");

  async function measureEndpoint(url: string, concurrency: number, totalReqs: number) {
    const latenciesMs: number[] = [];
    let errors = 0;
    const batchSize = concurrency;

    const t0 = performance.now();
    for (let i = 0; i < totalReqs; i += batchSize) {
      const batchCount = Math.min(batchSize, totalReqs - i);
      const promises = Array.from({ length: batchCount }, async () => {
        const s = performance.now();
        try {
          const res = await fetch(url);
          if (!res.ok) errors++;
        } catch {
          errors++;
        }
        latenciesMs.push(performance.now() - s);
      });
      await Promise.all(promises);
    }
    const totalTime = performance.now() - t0;
    const rps = (totalReqs / totalTime) * 1000;

    return {
      totalReqs,
      concurrency,
      errors,
      errorRate: (errors / totalReqs) * 100,
      rps,
      avg: latenciesMs.reduce((a, b) => a + b, 0) / latenciesMs.length,
      p50: calculatePercentile(latenciesMs, 50),
      p95: calculatePercentile(latenciesMs, 95),
      p99: calculatePercentile(latenciesMs, 99),
      max: Math.max(...latenciesMs),
    };
  }

  const healthPerf = await measureEndpoint("http://localhost:3000/api/health", 20, 100);
  console.log(`\nEndpoint: GET /api/health (100 reqs, concurrency 20)`);
  console.log(`Throughput:  ${healthPerf.rps.toFixed(1)} req/s`);
  console.log(`Avg Latency: ${healthPerf.avg.toFixed(2)} ms`);
  console.log(`P50:         ${healthPerf.p50.toFixed(2)} ms`);
  console.log(`P95:         ${healthPerf.p95.toFixed(2)} ms`);
  console.log(`P99:         ${healthPerf.p99.toFixed(2)} ms`);
  console.log(`Max:         ${healthPerf.max.toFixed(2)} ms`);
  console.log(`Error Rate:  ${healthPerf.errorRate.toFixed(1)}%`);

  const networkPerf = await measureEndpoint("http://localhost:3000/api/live-network", 10, 50);
  console.log(`\nEndpoint: GET /api/live-network (50 reqs, concurrency 10)`);
  console.log(`Throughput:  ${networkPerf.rps.toFixed(1)} req/s`);
  console.log(`Avg Latency: ${networkPerf.avg.toFixed(2)} ms`);
  console.log(`P50:         ${networkPerf.p50.toFixed(2)} ms`);
  console.log(`P95:         ${networkPerf.p95.toFixed(2)} ms`);
  console.log(`P99:         ${networkPerf.p99.toFixed(2)} ms`);
  console.log(`Max:         ${networkPerf.max.toFixed(2)} ms`);
  console.log(`Error Rate:  ${networkPerf.errorRate.toFixed(1)}%`);

  console.log("\n=================================================");
  console.log("   BENCHMARK & PERFORMANCE EVALUATION COMPLETE   ");
  console.log("=================================================");
}

runBenchmark().catch((err) => {
  console.error("Benchmark failed:", err);
  process.exit(1);
});
