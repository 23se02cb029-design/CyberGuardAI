/**
 * Deterministic SOC Copilot dialogue used whenever GEMINI_API_KEY is unset
 * or the live call fails — keeps the chat usable offline instead of
 * surfacing an error to the analyst.
 */
const DIALOGUE_TREES: Array<{ keywords: string[]; response: string }> = [
  {
    keywords: ["phishing", "email"],
    response:
      "**Phishing Triage**\n\nLook for spoofed sender domains, urgency language, and mismatched links. Immediate steps:\n1. Quarantine the message across all mailboxes it was delivered to.\n2. Check if any recipient clicked the link or submitted credentials — force a password reset if so.\n3. Block the sending domain/IP at the mail gateway.\n4. Report the indicators to your threat intel feed.",
  },
  {
    keywords: ["brute force", "brute-force", "failed login", "failed password", "ssh"],
    response:
      "**Brute Force Response**\n\nRepeated failed authentications usually precede credential compromise. Immediate steps:\n1. Block the source IP at the firewall.\n2. Confirm the targeted account wasn't ultimately compromised (check for a success after the failures).\n3. Enable MFA and rate-limiting on the affected service.\n4. Review other accounts for similar patterns from the same source.",
  },
  {
    keywords: ["malware", "ransomware", "virus", "trojan"],
    response:
      "**Malware Containment**\n\n1. Isolate the affected host from the network immediately.\n2. Preserve memory and disk artifacts before remediation.\n3. Identify the process tree and persistence mechanism (scheduled tasks, registry run keys, services).\n4. Rebuild from a known-good image rather than trusting in-place cleanup for anything beyond commodity malware.",
  },
  {
    keywords: ["exfiltration", "data loss", "dlp"],
    response:
      "**Data Exfiltration Response**\n\n1. Identify what data left, to where, and via which channel (email, cloud upload, USB).\n2. Revoke the account/session credentials involved.\n3. Check DLP and proxy logs for the full scope of transferred data.\n4. Notify legal/compliance if regulated data may be involved.",
  },
  {
    keywords: ["privilege escalation", "admin access", "sudo"],
    response:
      "**Privilege Escalation Response**\n\n1. Determine how elevated access was obtained (misconfiguration, stolen token, unpatched CVE).\n2. Revoke the elevated session and rotate any credentials it could have touched.\n3. Audit recently modified group memberships and IAM policies.\n4. Patch or reconfigure the escalation vector before restoring normal access.",
  },
  {
    keywords: ["risk score", "riskscore"],
    response:
      "Risk scores in CyberGuard AI range 0-100, weighing signal severity, asset criticality, and behavioral deviation from baseline. Scores ≥80 are CRITICAL, 60-79 HIGH, 40-59 ELEVATED, and below 40 NOMINAL.",
  },
];

const DEFAULT_RESPONSES = [
  "I'm running in offline fallback mode right now (no live Gemini connection), but I can still help — try asking about a specific threat type like phishing, brute force, malware, or data exfiltration.",
  "Live reasoning is currently unavailable, so I'm answering from my built-in SOC playbooks. Ask me about a threat category (e.g. \"how do I respond to a brute force attack?\") and I'll walk you through it.",
];

export function getFallbackCopilotResponse(message: string): string {
  const normalized = message.toLowerCase();
  const match = DIALOGUE_TREES.find((tree) =>
    tree.keywords.some((keyword) => normalized.includes(keyword))
  );
  if (match) return match.response;

  const index = normalized.length % DEFAULT_RESPONSES.length;
  return DEFAULT_RESPONSES[index];
}
