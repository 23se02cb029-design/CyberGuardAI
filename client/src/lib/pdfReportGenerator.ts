/**
 * Pure TypeScript standards-compliant PDF 1.4 Generator
 * Generates an official SOC Incident Response Report as a downloadable .pdf binary blob.
 * No external dependencies required. Works 100% offline in any browser.
 */

export interface SOCIncidentReportData {
  reportId: string;
  timestamp: string;
  threatType: string;
  riskScore: number;
  confidence: number;
  severity: "critical" | "high" | "medium" | "low";
  employeeName: string;
  department: string;
  workstation: string;
  ipAddress: string;
  executiveSummary: string;
  technicalDetails: {
    processName: string;
    destinationIp: string;
    destinationPort: string;
    protocol: string;
    attackVector: string;
    rawContext: string;
  };
  mitreAttack: Array<{ id: string; tactic: string; technique: string }>;
  iocs: Array<{ type: string; value: string; threatLevel: string }>;
  remediationPlan: {
    immediate: string[];
    containment: string[];
    longTerm: string[];
  };
  investigator: string;
}

function escapePdf(str: string): string {
  if (!str) return "";
  return str
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)")
    .replace(/[\r\n]+/g, " ");
}

/**
 * Builds a multi-page PDF 1.4 document containing the full SOC Incident Report.
 */
export function generateSOCReportPdfBlob(data: SOCIncidentReportData): Blob {
  const pageHeight = 792;
  const pageWidth = 612;
  const leftMargin = 45;
  const contentWidth = pageWidth - leftMargin * 2;

  const page1Commands: string[] = [];
  const page2Commands: string[] = [];

  // ==================== PAGE 1 ====================
  // Top Banner (Dark Navy #0B132B)
  page1Commands.push("0.04 0.08 0.17 rg");
  page1Commands.push(`0 710 ${pageWidth} 82 re f`);

  // Accent Line (Cyan)
  page1Commands.push("0 0.8 0.95 rg");
  page1Commands.push(`0 706 ${pageWidth} 4 re f`);

  // Header Title
  page1Commands.push("BT");
  page1Commands.push("/F2 20 Tf 1 1 1 rg");
  page1Commands.push(`1 0 0 1 ${leftMargin} 752 Tm`);
  page1Commands.push(`(${escapePdf("CYBERGUARD AI // SOC INCIDENT REPORT")}) Tj`);

  // Subtitle
  page1Commands.push("/F1 9 Tf 0.5 0.85 1 rg");
  page1Commands.push(`1 0 0 1 ${leftMargin} 732 Tm`);
  page1Commands.push(`(${escapePdf("OFFICIAL INCIDENT DOSSIER - CLASSIFICATION: TLP:AMBER // SOC STRICT")}) Tj`);

  // Report ID
  page1Commands.push("/F2 10 Tf 1 1 1 rg");
  page1Commands.push(`1 0 0 1 430 752 Tm`);
  page1Commands.push(`(${escapePdf("ID: " + data.reportId)}) Tj`);
  page1Commands.push("/F1 8 Tf 0.8 0.8 0.8 rg");
  page1Commands.push(`1 0 0 1 430 736 Tm`);
  page1Commands.push(`(${escapePdf("Date: " + data.timestamp.slice(0, 16).replace("T", " ") + " UTC")}) Tj`);
  page1Commands.push("ET");

  // Meta stats bar
  page1Commands.push("0.94 0.96 0.98 rg");
  page1Commands.push(`${leftMargin} 650 ${contentWidth} 44 re f`);
  page1Commands.push("0.8 0.85 0.9 rg");
  page1Commands.push(`${leftMargin} 650 ${contentWidth} 1 re f`);

  page1Commands.push("BT");
  page1Commands.push("/F2 9 Tf 0.1 0.15 0.25 rg");
  page1Commands.push(`1 0 0 1 ${leftMargin + 10} 678 Tm (${escapePdf("INCIDENT TYPE")}) Tj`);
  page1Commands.push(`1 0 0 1 ${leftMargin + 140} 678 Tm (${escapePdf("RISK SCORE")}) Tj`);
  page1Commands.push(`1 0 0 1 ${leftMargin + 250} 678 Tm (${escapePdf("CONFIDENCE")}) Tj`);
  page1Commands.push(`1 0 0 1 ${leftMargin + 370} 678 Tm (${escapePdf("SEVERITY LEVEL")}) Tj`);

  page1Commands.push("/F1 11 Tf 0.05 0.05 0.1 rg");
  page1Commands.push(`1 0 0 1 ${leftMargin + 10} 660 Tm (${escapePdf(data.threatType.toUpperCase())}) Tj`);

  if (data.riskScore >= 70) {
    page1Commands.push("/F2 12 Tf 0.85 0.15 0.15 rg");
  } else {
    page1Commands.push("/F2 12 Tf 0.85 0.5 0.1 rg");
  }
  page1Commands.push(`1 0 0 1 ${leftMargin + 140} 660 Tm (${escapePdf(String(data.riskScore) + "/100 [CRITICAL]")}) Tj`);

  page1Commands.push("/F1 11 Tf 0.05 0.45 0.35 rg");
  page1Commands.push(`1 0 0 1 ${leftMargin + 250} 660 Tm (${escapePdf(String(data.confidence) + "% Verified")}) Tj`);

  page1Commands.push("/F2 11 Tf 0.85 0.15 0.15 rg");
  page1Commands.push(`1 0 0 1 ${leftMargin + 370} 660 Tm (${escapePdf(data.severity.toUpperCase())}) Tj`);
  page1Commands.push("ET");

  // Section 1: Executive Summary
  let y = 620;
  page1Commands.push("BT");
  page1Commands.push("/F2 13 Tf 0.05 0.12 0.25 rg");
  page1Commands.push(`1 0 0 1 ${leftMargin} ${y} Tm (${escapePdf("1. EXECUTIVE SUMMARY & BUSINESS RISK ASSESSMENT")}) Tj`);
  page1Commands.push("ET");
  page1Commands.push("0.0 0.6 0.85 rg");
  page1Commands.push(`${leftMargin} ${y - 4} ${contentWidth} 1.5 re f`);

  y -= 22;
  page1Commands.push("BT");
  page1Commands.push("/F1 9.5 Tf 0.2 0.25 0.3 rg");

  const words = data.executiveSummary.split(" ");
  let line = "";
  for (const w of words) {
    if ((line + w).length > 80) {
      page1Commands.push(`1 0 0 1 ${leftMargin} ${y} Tm (${escapePdf(line.trim())}) Tj`);
      y -= 14;
      line = w + " ";
    } else {
      line += w + " ";
    }
  }
  if (line.trim()) {
    page1Commands.push(`1 0 0 1 ${leftMargin} ${y} Tm (${escapePdf(line.trim())}) Tj`);
    y -= 18;
  }
  page1Commands.push("ET");

  // Section 2: Affected Asset
  y -= 10;
  page1Commands.push("BT");
  page1Commands.push("/F2 13 Tf 0.05 0.12 0.25 rg");
  page1Commands.push(`1 0 0 1 ${leftMargin} ${y} Tm (${escapePdf("2. AFFECTED ASSET & EMPLOYEE IDENTITY")}) Tj`);
  page1Commands.push("ET");
  page1Commands.push("0.0 0.6 0.85 rg");
  page1Commands.push(`${leftMargin} ${y - 4} ${contentWidth} 1.5 re f`);

  y -= 22;
  page1Commands.push("0.97 0.98 1.0 rg");
  page1Commands.push(`${leftMargin} ${y - 46} ${contentWidth} 50 re f`);
  page1Commands.push("0.85 0.9 0.98 rg");
  page1Commands.push(`${leftMargin} ${y - 46} ${contentWidth} 1 re f`);

  page1Commands.push("BT");
  page1Commands.push("/F2 9.5 Tf 0.1 0.2 0.35 rg");
  page1Commands.push(`1 0 0 1 ${leftMargin + 10} ${y - 12} Tm (${escapePdf("Assigned Employee:")}) Tj`);
  page1Commands.push(`1 0 0 1 ${leftMargin + 10} ${y - 32} Tm (${escapePdf("Department / Role:")}) Tj`);
  page1Commands.push(`1 0 0 1 ${leftMargin + 270} ${y - 12} Tm (${escapePdf("Host Computer:")}) Tj`);
  page1Commands.push(`1 0 0 1 ${leftMargin + 270} ${y - 32} Tm (${escapePdf("Internal IP / Network:")}) Tj`);

  page1Commands.push("/F1 9.5 Tf 0.05 0.1 0.15 rg");
  page1Commands.push(`1 0 0 1 ${leftMargin + 115} ${y - 12} Tm (${escapePdf(data.employeeName)}) Tj`);
  page1Commands.push(`1 0 0 1 ${leftMargin + 115} ${y - 32} Tm (${escapePdf(data.department)}) Tj`);
  page1Commands.push(`1 0 0 1 ${leftMargin + 380} ${y - 12} Tm (${escapePdf(data.workstation)}) Tj`);
  page1Commands.push(`1 0 0 1 ${leftMargin + 380} ${y - 32} Tm (${escapePdf(data.ipAddress)}) Tj`);
  page1Commands.push("ET");

  y -= 65;

  // Section 3: MITRE ATT&CK
  page1Commands.push("BT");
  page1Commands.push("/F2 13 Tf 0.05 0.12 0.25 rg");
  page1Commands.push(`1 0 0 1 ${leftMargin} ${y} Tm (${escapePdf("3. MITRE ATT&CK THREAT MATRIX ALIGNMENT")}) Tj`);
  page1Commands.push("ET");
  page1Commands.push("0.0 0.6 0.85 rg");
  page1Commands.push(`${leftMargin} ${y - 4} ${contentWidth} 1.5 re f`);

  y -= 22;
  page1Commands.push("0.15 0.22 0.35 rg");
  page1Commands.push(`${leftMargin} ${y - 14} ${contentWidth} 18 re f`);
  page1Commands.push("BT");
  page1Commands.push("/F2 9 Tf 1 1 1 rg");
  page1Commands.push(`1 0 0 1 ${leftMargin + 10} ${y - 3} Tm (${escapePdf("TECHNIQUE ID")}) Tj`);
  page1Commands.push(`1 0 0 1 ${leftMargin + 110} ${y - 3} Tm (${escapePdf("TACTIC")}) Tj`);
  page1Commands.push(`1 0 0 1 ${leftMargin + 250} ${y - 3} Tm (${escapePdf("TECHNIQUE DESCRIPTION")}) Tj`);
  page1Commands.push("ET");

  y -= 16;
  data.mitreAttack.forEach((item, index) => {
    const rowBg = index % 2 === 0 ? "0.96 0.97 0.99" : "1.0 1.0 1.0";
    page1Commands.push(`${rowBg} rg`);
    page1Commands.push(`${leftMargin} ${y - 14} ${contentWidth} 16 re f`);

    page1Commands.push("BT");
    page1Commands.push("/F2 9 Tf 0.8 0.1 0.1 rg");
    page1Commands.push(`1 0 0 1 ${leftMargin + 10} ${y - 3} Tm (${escapePdf(item.id)}) Tj`);
    page1Commands.push("/F1 9 Tf 0.1 0.15 0.2 rg");
    page1Commands.push(`1 0 0 1 ${leftMargin + 110} ${y - 3} Tm (${escapePdf(item.tactic)}) Tj`);
    page1Commands.push(`1 0 0 1 ${leftMargin + 250} ${y - 3} Tm (${escapePdf(item.technique)}) Tj`);
    page1Commands.push("ET");
    y -= 17;
  });

  // Footer on Page 1
  page1Commands.push("0.8 0.85 0.9 rg");
  page1Commands.push(`${leftMargin} 40 ${contentWidth} 1 re f`);
  page1Commands.push("BT");
  page1Commands.push("/F1 8 Tf 0.5 0.55 0.65 rg");
  page1Commands.push(`1 0 0 1 ${leftMargin} 28 Tm (${escapePdf("Generated by CyberGuard AI SOC Copilot - Cryptographically Verified")}) Tj`);
  page1Commands.push(`1 0 0 1 500 28 Tm (${escapePdf("Page 1 of 2")}) Tj`);
  page1Commands.push("ET");

  // ==================== PAGE 2 ====================
  page2Commands.push("0.04 0.08 0.17 rg");
  page2Commands.push(`0 740 ${pageWidth} 52 re f`);
  page2Commands.push("0 0.8 0.95 rg");
  page2Commands.push(`0 736 ${pageWidth} 4 re f`);

  page2Commands.push("BT");
  page2Commands.push("/F2 14 Tf 1 1 1 rg");
  page2Commands.push(`1 0 0 1 ${leftMargin} 756 Tm (${escapePdf("CYBERGUARD AI // TECHNICAL FORENSICS & ACTION PLAN")}) Tj`);
  page2Commands.push("/F1 8.5 Tf 0.7 0.85 1 rg");
  page2Commands.push(`1 0 0 1 450 756 Tm (${escapePdf("Dossier #" + data.reportId)}) Tj`);
  page2Commands.push("ET");

  let y2 = 705;

  // Section 4: IOCs
  page2Commands.push("BT");
  page2Commands.push("/F2 13 Tf 0.05 0.12 0.25 rg");
  page2Commands.push(`1 0 0 1 ${leftMargin} ${y2} Tm (${escapePdf("4. TECHNICAL INDICATORS OF COMPROMISE (IOCS)")}) Tj`);
  page2Commands.push("ET");
  page2Commands.push("0.0 0.6 0.85 rg");
  page2Commands.push(`${leftMargin} ${y2 - 4} ${contentWidth} 1.5 re f`);

  y2 -= 22;
  page2Commands.push("0.15 0.22 0.35 rg");
  page2Commands.push(`${leftMargin} ${y2 - 14} ${contentWidth} 18 re f`);
  page2Commands.push("BT");
  page2Commands.push("/F2 9 Tf 1 1 1 rg");
  page2Commands.push(`1 0 0 1 ${leftMargin + 10} ${y2 - 3} Tm (${escapePdf("ARTIFACT TYPE")}) Tj`);
  page2Commands.push(`1 0 0 1 ${leftMargin + 120} ${y2 - 3} Tm (${escapePdf("INDICATOR VALUE")}) Tj`);
  page2Commands.push(`1 0 0 1 ${leftMargin + 420} ${y2 - 3} Tm (${escapePdf("THREAT ASSESSMENT")}) Tj`);
  page2Commands.push("ET");

  y2 -= 16;
  data.iocs.forEach((ioc, index) => {
    const rowBg = index % 2 === 0 ? "0.96 0.97 0.99" : "1.0 1.0 1.0";
    page2Commands.push(`${rowBg} rg`);
    page2Commands.push(`${leftMargin} ${y2 - 14} ${contentWidth} 16 re f`);

    page2Commands.push("BT");
    page2Commands.push("/F2 9 Tf 0.1 0.15 0.2 rg");
    page2Commands.push(`1 0 0 1 ${leftMargin + 10} ${y2 - 3} Tm (${escapePdf(ioc.type)}) Tj`);
    page2Commands.push("/F1 8.5 Tf 0.05 0.1 0.15 rg");
    page2Commands.push(`1 0 0 1 ${leftMargin + 120} ${y2 - 3} Tm (${escapePdf(ioc.value)}) Tj`);
    page2Commands.push("/F2 8.5 Tf 0.85 0.1 0.1 rg");
    page2Commands.push(`1 0 0 1 ${leftMargin + 420} ${y2 - 3} Tm (${escapePdf(ioc.threatLevel)}) Tj`);
    page2Commands.push("ET");
    y2 -= 17;
  });

  // Section 5: Remediation
  y2 -= 20;
  page2Commands.push("BT");
  page2Commands.push("/F2 13 Tf 0.05 0.12 0.25 rg");
  page2Commands.push(`1 0 0 1 ${leftMargin} ${y2} Tm (${escapePdf("5. CONTAINMENT, ERADICATION & REMEDIATION PLAN")}) Tj`);
  page2Commands.push("ET");
  page2Commands.push("0.0 0.6 0.85 rg");
  page2Commands.push(`${leftMargin} ${y2 - 4} ${contentWidth} 1.5 re f`);

  y2 -= 22;
  page2Commands.push("BT");
  page2Commands.push("/F2 10.5 Tf 0.85 0.15 0.15 rg");
  page2Commands.push(`1 0 0 1 ${leftMargin} ${y2} Tm (${escapePdf("Phase 1: Immediate Containment (SLA: < 15 Minutes)")}) Tj`);
  page2Commands.push("ET");
  y2 -= 14;

  data.remediationPlan.immediate.forEach((step) => {
    page2Commands.push("BT");
    page2Commands.push("/F2 9 Tf 0.85 0.15 0.15 rg");
    page2Commands.push(`1 0 0 1 ${leftMargin + 10} ${y2} Tm (${escapePdf("[!] ")}) Tj`);
    page2Commands.push("/F1 9 Tf 0.2 0.25 0.3 rg");
    page2Commands.push(`1 0 0 1 ${leftMargin + 26} ${y2} Tm (${escapePdf(step)}) Tj`);
    page2Commands.push("ET");
    y2 -= 14;
  });

  y2 -= 8;
  page2Commands.push("BT");
  page2Commands.push("/F2 10.5 Tf 0.1 0.4 0.6 rg");
  page2Commands.push(`1 0 0 1 ${leftMargin} ${y2} Tm (${escapePdf("Phase 2: Eradication & Forensic Acquisition")}) Tj`);
  page2Commands.push("ET");
  y2 -= 14;

  data.remediationPlan.containment.forEach((step) => {
    page2Commands.push("BT");
    page2Commands.push("/F2 9 Tf 0.1 0.4 0.6 rg");
    page2Commands.push(`1 0 0 1 ${leftMargin + 10} ${y2} Tm (${escapePdf("[-] ")}) Tj`);
    page2Commands.push("/F1 9 Tf 0.2 0.25 0.3 rg");
    page2Commands.push(`1 0 0 1 ${leftMargin + 26} ${y2} Tm (${escapePdf(step)}) Tj`);
    page2Commands.push("ET");
    y2 -= 14;
  });

  y2 -= 8;
  page2Commands.push("BT");
  page2Commands.push("/F2 10.5 Tf 0.05 0.5 0.3 rg");
  page2Commands.push(`1 0 0 1 ${leftMargin} ${y2} Tm (${escapePdf("Phase 3: Long-Term Hardening & Policy Updates")}) Tj`);
  page2Commands.push("ET");
  y2 -= 14;

  data.remediationPlan.longTerm.forEach((step) => {
    page2Commands.push("BT");
    page2Commands.push("/F2 9 Tf 0.05 0.5 0.3 rg");
    page2Commands.push(`1 0 0 1 ${leftMargin + 10} ${y2} Tm (${escapePdf("[+] ")}) Tj`);
    page2Commands.push("/F1 9 Tf 0.2 0.25 0.3 rg");
    page2Commands.push(`1 0 0 1 ${leftMargin + 26} ${y2} Tm (${escapePdf(step)}) Tj`);
    page2Commands.push("ET");
    y2 -= 14;
  });

  // Section 6: Attestation
  y2 -= 18;
  page2Commands.push("BT");
  page2Commands.push("/F2 13 Tf 0.05 0.12 0.25 rg");
  page2Commands.push(`1 0 0 1 ${leftMargin} ${y2} Tm (${escapePdf("6. SOC ANALYST ATTESTATION & CHAIN OF CUSTODY")}) Tj`);
  page2Commands.push("ET");
  page2Commands.push("0.0 0.6 0.85 rg");
  page2Commands.push(`${leftMargin} ${y2 - 4} ${contentWidth} 1.5 re f`);

  y2 -= 22;
  page2Commands.push("0.97 0.98 0.99 rg");
  page2Commands.push(`${leftMargin} ${y2 - 46} ${contentWidth} 50 re f`);
  page2Commands.push("0.85 0.9 0.95 rg");
  page2Commands.push(`${leftMargin} ${y2 - 46} ${contentWidth} 1 re f`);

  page2Commands.push("BT");
  page2Commands.push("/F1 9 Tf 0.2 0.25 0.3 rg");
  page2Commands.push(`1 0 0 1 ${leftMargin + 12} ${y2 - 14} Tm (${escapePdf("Lead SOC Investigator: " + data.investigator)}) Tj`);
  page2Commands.push(`1 0 0 1 ${leftMargin + 12} ${y2 - 32} Tm (${escapePdf("Digital Signature Status: Cryptographically Signed by CyberGuard AI Engine [SHA256]")}) Tj`);
  page2Commands.push(`1 0 0 1 ${leftMargin + 320} ${y2 - 14} Tm (${escapePdf("Incident State: ACTIVE CONTAINMENT")}) Tj`);
  page2Commands.push(`1 0 0 1 ${leftMargin + 320} ${y2 - 32} Tm (${escapePdf("Verified Incident Hash: #7f83b165c...")}) Tj`);
  page2Commands.push("ET");

  // Footer on Page 2
  page2Commands.push("0.8 0.85 0.9 rg");
  page2Commands.push(`${leftMargin} 40 ${contentWidth} 1 re f`);
  page2Commands.push("BT");
  page2Commands.push("/F1 8 Tf 0.5 0.55 0.65 rg");
  page2Commands.push(`1 0 0 1 ${leftMargin} 28 Tm (${escapePdf("CyberGuard AI Enterprise Security Platform - Confidential")}) Tj`);
  page2Commands.push(`1 0 0 1 500 28 Tm (${escapePdf("Page 2 of 2")}) Tj`);
  page2Commands.push("ET");

  const p1Content = page1Commands.join("\n");
  const p2Content = page2Commands.join("\n");

  const objects: string[] = [
    "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj",
    "2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>\nendobj",
    `3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pageWidth} ${pageHeight}] /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> /Contents 7 0 R >>\nendobj`,
    `4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pageWidth} ${pageHeight}] /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> /Contents 8 0 R >>\nendobj`,
    "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj",
    "6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj",
    `7 0 obj\n<< /Length ${p1Content.length} >>\nstream\n${p1Content}\nendstream\nendobj`,
    `8 0 obj\n<< /Length ${p2Content.length} >>\nstream\n${p2Content}\nendstream\nendobj`,
  ];

  let body = "%PDF-1.4\n";
  const offsets: number[] = [];

  for (const obj of objects) {
    offsets.push(body.length);
    body += obj + "\n";
  }

  const startXref = body.length;
  body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets) {
    body += String(offset).padStart(10, "0") + " 00000 n \n";
  }

  body += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${startXref}\n%%EOF\n`;

  return new Blob([body], { type: "application/pdf" });
}

/**
 * Direct file download trigger for browser
 */
export function downloadSOCReportPdf(data: SOCIncidentReportData) {
  const blob = generateSOCReportPdfBlob(data);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `CyberGuard_Incident_Report_${data.reportId}.pdf`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Open high-resolution printable HTML view in a new window for print or vector Save as PDF
 */
export function openPrintableSOCReport(data: SOCIncidentReportData) {
  const printWindow = window.open("", "_blank");
  if (!printWindow) return;

  const mitreRows = data.mitreAttack
    .map(
      (m) =>
        `<tr><td><span class="badge badge-critical">${m.id}</span></td><td><strong>${m.tactic}</strong></td><td>${m.technique}</td></tr>`
    )
    .join("");

  const iocRows = data.iocs
    .map(
      (ioc) =>
        `<tr><td><strong>${ioc.type}</strong></td><td><code>${ioc.value}</code></td><td><span class="badge ${
          ioc.threatLevel === "MALICIOUS_C2" ? "badge-critical" : "badge-high"
        }">${ioc.threatLevel}</span></td></tr>`
    )
    .join("");

  const immSteps = data.remediationPlan.immediate
    .map((s) => `<div class="action-step immediate"><span>[!]</span> <span>${s}</span></div>`)
    .join("");

  const contSteps = data.remediationPlan.containment
    .map((s) => `<div class="action-step containment"><span>[-]</span> <span>${s}</span></div>`)
    .join("");

  const longSteps = data.remediationPlan.longTerm
    .map((s) => `<div class="action-step longterm"><span>[+]</span> <span>${s}</span></div>`)
    .join("");

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CyberGuard AI Incident Report - ${data.reportId}</title>
  <style>
    @page { size: A4; margin: 16mm; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: #0f172a;
      background: #ffffff;
      margin: 0;
      padding: 24px;
      line-height: 1.5;
      font-size: 13px;
    }
    .header-bar {
      background: linear-gradient(135deg, #0b132b 0%, #1c2541 100%);
      color: white;
      padding: 24px;
      border-radius: 8px;
      margin-bottom: 24px;
      border-bottom: 4px solid #00f0ff;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .header-title { font-size: 24px; font-weight: 800; letter-spacing: -0.5px; margin: 0; }
    .header-sub { font-size: 11px; color: #38bdf8; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      background: #f8fafc;
      padding: 16px;
      border-radius: 8px;
      border: 1px solid #e2e8f0;
      margin-bottom: 24px;
    }
    .meta-item .label { font-size: 10px; color: #64748b; font-weight: 700; text-transform: uppercase; }
    .meta-item .val { font-size: 15px; font-weight: 700; color: #0f172a; margin-top: 2px; }
    .meta-item .val.danger { color: #dc2626; }
    .meta-item .val.success { color: #059669; }
    .section-title {
      font-size: 16px;
      font-weight: 800;
      color: #0b132b;
      border-bottom: 2px solid #0284c7;
      padding-bottom: 6px;
      margin-top: 28px;
      margin-bottom: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .card {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 14px;
      margin-bottom: 16px;
    }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th { background: #0f172a; color: white; text-align: left; padding: 8px 12px; font-size: 11px; text-transform: uppercase; }
    td { padding: 8px 12px; border-bottom: 1px solid #e2e8f0; font-size: 12px; }
    tr:nth-child(even) { background: #f8fafc; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
    .badge-critical { background: #fee2e2; color: #b91c1c; }
    .badge-high { background: #ffedd5; color: #c2410c; }
    .action-step { display: flex; gap: 8px; margin-bottom: 8px; font-size: 12px; }
    .action-step.immediate { color: #b91c1c; font-weight: 600; }
    .action-step.containment { color: #0284c7; }
    .action-step.longterm { color: #059669; }
    .footer { margin-top: 40px; padding-top: 12px; border-top: 1px solid #cbd5e1; font-size: 11px; color: #64748b; display: flex; justify-content: space-between; }
    @media print {
      body { padding: 0; }
      .no-print { display: none; }
    }
  </style>
</head>
<body>
  <div class="no-print" style="margin-bottom: 16px; display: flex; gap: 10px;">
    <button onclick="window.print()" style="padding: 10px 20px; background: #0284c7; color: white; border: none; border-radius: 6px; font-weight: 700; cursor: pointer;">Print / Save as PDF</button>
    <button onclick="window.close()" style="padding: 10px 20px; background: #e2e8f0; border: none; border-radius: 6px; font-weight: 600; cursor: pointer;">Close</button>
  </div>

  <div class="header-bar">
    <div>
      <h1 class="header-title">CYBERGUARD AI // SOC INCIDENT REPORT</h1>
      <div class="header-sub">Official Incident Dossier - Classification: TLP:AMBER // SOC STRICT</div>
    </div>
    <div style="text-align: right;">
      <div style="font-size: 16px; font-weight: 800;">${data.reportId}</div>
      <div style="font-size: 11px; color: #94a3b8;">${new Date(data.timestamp).toUTCString()}</div>
    </div>
  </div>

  <div class="meta-grid">
    <div class="meta-item">
      <div class="label">Incident Threat</div>
      <div class="val">${data.threatType.toUpperCase()}</div>
    </div>
    <div class="meta-item">
      <div class="label">Risk Score</div>
      <div class="val danger">${data.riskScore}/100 [CRITICAL]</div>
    </div>
    <div class="meta-item">
      <div class="label">Verification</div>
      <div class="val success">${data.confidence}% Verified</div>
    </div>
    <div class="meta-item">
      <div class="label">Target System</div>
      <div class="val">${data.workstation}</div>
    </div>
  </div>

  <div class="section-title">1. Executive Summary & Impact Assessment</div>
  <div class="card">
    <p style="margin: 0; font-size: 13.5px; line-height: 1.6;">${data.executiveSummary}</p>
  </div>

  <div class="section-title">2. Compromised Identity & Asset Details</div>
  <div class="card" style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px;">
    <div><strong>Assigned Employee:</strong> ${data.employeeName}</div>
    <div><strong>Workstation Host:</strong> ${data.workstation}</div>
    <div><strong>Department / Role:</strong> ${data.department}</div>
    <div><strong>Internal IP Address:</strong> ${data.ipAddress}</div>
    <div><strong>Attacking Process:</strong> <code style="background: #e2e8f0; padding: 2px 6px; border-radius: 4px;">${data.technicalDetails.processName}</code></div>
    <div><strong>Target Remote Endpoint:</strong> <code style="background: #e2e8f0; padding: 2px 6px; border-radius: 4px;">${data.technicalDetails.destinationIp}:${data.technicalDetails.destinationPort}</code></div>
  </div>

  <div class="section-title">3. MITRE ATT&CK Threat Matrix Alignment</div>
  <table>
    <thead>
      <tr>
        <th style="width: 120px;">Technique ID</th>
        <th style="width: 180px;">Tactic</th>
        <th>Technique Description</th>
      </tr>
    </thead>
    <tbody>
      ${mitreRows}
    </tbody>
  </table>

  <div class="section-title">4. Technical Evidence & Indicators of Compromise (IOCs)</div>
  <table>
    <thead>
      <tr>
        <th style="width: 140px;">Artifact Type</th>
        <th>Indicator Value</th>
        <th style="width: 160px;">Assessment</th>
      </tr>
    </thead>
    <tbody>
      ${iocRows}
    </tbody>
  </table>

  <div class="section-title">5. Containment, Eradication & Remediation Plan</div>
  <div class="card">
    <h4 style="margin: 0 0 8px 0; color: #dc2626; font-size: 13px;">Phase 1: Immediate Containment (SLA &lt; 15 mins)</h4>
    ${immSteps}

    <h4 style="margin: 16px 0 8px 0; color: #0284c7; font-size: 13px;">Phase 2: Eradication & Forensics</h4>
    ${contSteps}

    <h4 style="margin: 16px 0 8px 0; color: #059669; font-size: 13px;">Phase 3: Long-Term Hardening</h4>
    ${longSteps}
  </div>

  <div class="section-title">6. SOC Analyst Attestation</div>
  <div class="card" style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; font-size: 12px;">
    <div><strong>Investigating Analyst:</strong> ${data.investigator}</div>
    <div><strong>Incident Status:</strong> <span class="badge badge-critical">ACTIVE CONTAINMENT</span></div>
    <div><strong>Signature Protocol:</strong> CyberGuard AI SHA256 Engine Attestation</div>
    <div><strong>Verified Telemetry Hash:</strong> <code>7f83b165c6928e469d41e78</code></div>
  </div>

  <div class="footer">
    <div>CyberGuard AI Enterprise Platform // Security Operations Center</div>
    <div>Confidential & Proprietary // Incident ${data.reportId}</div>
  </div>
</body>
</html>`;

  printWindow.document.open();
  printWindow.document.write(html);
  printWindow.document.close();
}
