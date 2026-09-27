# CyberGuard AI - User Guide

## Getting Started

Welcome to CyberGuard AI, your AI-powered Security Operations Center (SOC) Copilot. This guide will help you get the most out of the platform.

---

## Dashboard Overview

The main dashboard provides a real-time overview of your security posture:

### Key Metrics

1. **Average Risk Score** - Overall threat level (0-100)
2. **Total Threats Detected** - Cumulative threat count
3. **Critical Threats** - High-priority incidents requiring immediate attention
4. **Security Status** - Real-time security health indicator

### Navigation

- **Upload Logs** - Add security logs for analysis
- **Analyze Threats** - Run threat detection on uploaded logs
- **Generate Report** - Create incident reports
- **SOC Copilot** - Chat with AI assistant

---

## Uploading Security Logs

### Supported Formats

CyberGuard AI accepts logs from multiple sources:

1. **Firewall Logs**
   - Format: Syslog or CSV
   - Fields: timestamp, source IP, destination IP, action, protocol

2. **IDS/IPS Logs**
   - Format: JSON or CSV
   - Fields: alert type, signature, source/destination, severity

3. **Authentication Server Logs**
   - Format: Syslog or JSON
   - Fields: timestamp, user, login status, source IP

4. **Endpoint Logs**
   - Format: JSON or CSV
   - Fields: process name, file access, network connection, user

5. **SIEM Logs**
   - Format: JSON or CSV
   - Fields: event type, severity, source, destination

### Upload Process

1. Navigate to **Upload Logs** page
2. Select log source type (Firewall, IDS, Auth Server, etc.)
3. Drag and drop file or click to browse
4. Click **Upload & Analyze**
5. Wait for processing to complete

### Example Log Formats

**CSV Format:**
```csv
timestamp,source_ip,destination_ip,user,event_type,severity
2026-01-24 12:00:00,192.168.1.100,10.0.0.50,john.doe,login_attempt,low
2026-01-24 12:01:00,192.168.1.101,10.0.0.51,jane.smith,file_access,medium
```

**JSON Format:**
```json
[
  {
    "timestamp": "2026-01-24T12:00:00Z",
    "sourceIp": "192.168.1.100",
    "destinationIp": "10.0.0.50",
    "userId": "john.doe",
    "eventType": "login_attempt",
    "severity": "low"
  }
]
```

**Syslog Format:**
```
Jan 24 12:00:00 firewall kernel: Connection from 192.168.1.100 to 10.0.0.50
Jan 24 12:01:00 firewall kernel: Failed login attempt for user admin
```

---

## Threat Detection

### Understanding Threat Classifications

CyberGuard AI classifies threats into seven categories:

1. **Phishing** 🎣
   - Email-based social engineering attacks
   - Suspicious links or attachments
   - Credential harvesting attempts

2. **Brute Force** ⚡
   - Multiple failed login attempts
   - Password guessing attacks
   - Credential stuffing

3. **Malware** 🦠
   - Suspicious file execution
   - Unauthorized process behavior
   - File integrity violations

4. **Lateral Movement** 👁️
   - Unauthorized network traversal
   - Privilege escalation attempts
   - Unusual access patterns

5. **Data Exfiltration** 📤
   - Unauthorized data access
   - Large data transfers
   - Suspicious export activities

6. **Privilege Escalation** ⚡
   - Unauthorized privilege elevation
   - Sudo/admin command abuse
   - Role elevation attempts

7. **Unknown** ❓
   - Unclassified security events
   - Anomalous behavior
   - Requires manual review

### Risk Scoring

Risk scores (0-100) indicate threat severity:

| Score | Level | Action |
|-------|-------|--------|
| 0-40 | Low | Monitor |
| 41-60 | Medium | Investigate |
| 61-80 | High | Urgent response |
| 81-100 | Critical | Immediate action |

### MITRE ATT&CK Framework

Each threat is mapped to MITRE ATT&CK techniques for standardized threat intelligence:

- **T1110** - Brute Force
- **T1566** - Phishing
- **T1566.002** - Phishing: Spearphishing Link
- **T1547** - Boot or Logon Autostart Execution

---

## Threat Analysis

### Viewing Threat Details

1. Navigate to **Threats** page
2. Click on any threat to view details
3. Review:
   - Threat classification
   - Risk score and confidence
   - MITRE ATT&CK mappings
   - Affected assets
   - Indicators of compromise

### Threat Status Management

Update threat status as you investigate:

- **New** - Newly detected threat
- **Investigating** - Currently under review
- **Confirmed** - Verified as genuine threat
- **False Positive** - Not a real threat
- **Resolved** - Threat mitigated

---

## SOC Copilot Chat

### AI Assistant Features

CyberGuard AI's SOC Copilot is an intelligent assistant that can:

- Answer questions about security logs
- Explain threat detections
- Recommend incident response actions
- Generate reports
- Provide security insights

### Example Questions

**Understanding Threats:**
- "What threats were detected in the last 24 hours?"
- "Explain the brute force attack in detail"
- "What does this MITRE ATT&CK ID mean?"

**Incident Response:**
- "What should we do about the critical threats?"
- "How do we prevent brute force attacks?"
- "What are the immediate actions needed?"

**Reporting:**
- "Generate a report for the critical threats"
- "Create an executive summary of today's incidents"
- "What's the impact of these threats?"

**Analysis:**
- "Compare threat types by frequency"
- "Which user accounts are most targeted?"
- "What's the trend in threat severity?"

### Chat Tips

1. **Be Specific** - Provide context for better answers
2. **Ask Follow-ups** - Clarify or dive deeper
3. **Use Chat History** - Reference previous discussions
4. **Copy Responses** - Save important information

---

## Incident Response

### Response Recommendations

For each threat, CyberGuard AI provides:

1. **Short-Term Actions** (0-24 hours)
   - Immediate steps to contain the threat
   - Examples: Isolate systems, reset credentials

2. **Long-Term Actions** (1-30 days)
   - Strategic improvements
   - Examples: Implement MFA, deploy IDS

3. **Priority Level**
   - Critical: Immediate action required
   - High: Urgent response needed
   - Medium: Address within 24-48 hours
   - Low: Plan for next security cycle

### Implementation Workflow

1. Review threat details
2. Check recommended actions
3. Assign tasks to responsible teams
4. Track completion status
5. Update threat status when resolved

---

## Report Generation

### Report Types

1. **Executive Report**
   - Business impact summary
   - Key findings and recommendations
   - Risk assessment
   - Best for: Leadership, board presentations

2. **Technical Report**
   - Detailed technical analysis
   - Indicators of compromise (IOCs)
   - MITRE ATT&CK mappings
   - Best for: SOC teams, incident response

3. **Combined Report**
   - Both executive and technical sections
   - Comprehensive incident documentation
   - Best for: Compliance, audits

### Generating Reports

1. Navigate to threat details
2. Click **Generate Report**
3. Select report type
4. Review generated report
5. Download as PDF

### Report Contents

- Executive summary
- Threat classification
- Risk assessment
- Affected assets
- Indicators of compromise
- Recommended actions
- MITRE ATT&CK mappings
- Timeline of events

---

## Dashboard Analytics

### Threat Timeline

Visualize threats over time:
- X-axis: Time period
- Y-axis: Threat count or risk score
- Hover for details

### Threat Distribution

See threat types by frequency:
- Pie chart showing threat type breakdown
- Identify most common threats
- Plan defenses accordingly

### Risk Score Trends

Monitor security posture changes:
- Trending up: Increasing threats
- Trending down: Improving security
- Baseline: Normal activity level

---

## Best Practices

### Log Management

1. **Upload Regularly**
   - Daily uploads for real-time detection
   - Include all security sources
   - Maintain consistent format

2. **Log Retention**
   - Keep 90 days minimum
   - Archive older logs
   - Maintain backup copies

3. **Log Quality**
   - Ensure accurate timestamps
   - Include all relevant fields
   - Remove sensitive data if needed

### Threat Response

1. **Act Quickly**
   - Critical threats: Respond within 1 hour
   - High threats: Respond within 4 hours
   - Medium threats: Respond within 24 hours

2. **Document Everything**
   - Record actions taken
   - Save evidence
   - Update threat status

3. **Learn from Incidents**
   - Review root causes
   - Implement preventive measures
   - Share lessons learned

### Security Hygiene

1. **Multi-Factor Authentication (MFA)**
   - Enable for all user accounts
   - Use authenticator apps
   - Backup recovery codes

2. **Access Control**
   - Principle of least privilege
   - Regular access reviews
   - Remove unused accounts

3. **Monitoring**
   - Enable continuous logging
   - Monitor privileged accounts
   - Alert on suspicious activity

---

## Troubleshooting

### Common Issues

**Q: Upload failed - what should I do?**
A: Check file format, ensure it's valid CSV/JSON/syslog, verify file size < 100MB

**Q: Threat detection seems inaccurate**
A: Review threat details, check MITRE mappings, provide feedback for improvement

**Q: Chat response is slow**
A: This is normal for complex queries. Wait for response, try simpler questions

**Q: Can't download report**
A: Refresh page, try different browser, check internet connection

### Getting Help
- **Support**: amitshibag72@gmail.com
---

## Security & Privacy

### Data Protection

- All data encrypted in transit (TLS)
- Data encrypted at rest (AES-256)
- Regular security audits
- Compliance: SOC 2, ISO 27001

### Privacy

- Your data is yours
- No third-party sharing
- GDPR compliant
- Data retention policies enforced

### Compliance

- HIPAA ready
- PCI DSS compatible
- NIST Cybersecurity Framework aligned
- CIS Controls mapping available

---

## Tips & Tricks

1. **Keyboard Shortcuts**
   - `/` - Open command palette
   - `?` - Show help
   - `Ctrl+K` - Search threats

2. **Bulk Operations**
   - Select multiple threats
   - Bulk update status
   - Bulk export reports

3. **Custom Filters**
   - Filter by threat type
   - Filter by risk score
   - Filter by date range

4. **Export Data**
   - Export threats as CSV
   - Export reports as PDF
   - Export chat history

---

## Feedback & Feature Requests

We'd love to hear from you!

- **Bug Reports**: GitHub Issues
- **Feature Requests**: Feature board
- **General Feedback**: amitshibag72@gmail.com

## Version History

- **v1.0.0** (2026-01-24) - Initial release
  - Log ingestion and normalization
  - AI-powered threat detection
  - SOC Copilot chat interface
  - Report generation
  - Dashboard analytics

---

Last updated: January 24, 2026
