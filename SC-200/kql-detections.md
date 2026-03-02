# SC-200 Study  KQL Detection Notes

Working through SC-200 objectives. These are my study notes with KQL queries I have written and tested against Microsoft Sentinel / Defender XDR sample data.

---

## Module: Detect Threats Using KQL

### 1. Failed Sign-in Spike (Brute Force Indicator)

```kql
SigninLogs
| where ResultType != "0"  // non-zero = failure
| summarize FailCount = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailCount > 10
| order by FailCount desc
```

**What it does:** Groups failed logins by user and IP in 5-minute windows. More than 10 failures in a window is suspicious and may indicate brute force.

---

### 2. New Process Created by Office Application

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

**What it does:** Detects when Office applications spawn command-line tools  a common indicator of macro-based malware execution.

---

### 3. Large Data Exfiltration Over HTTP

```kql
DeviceNetworkEvents
| where RemotePort == 80 or RemotePort == 443
| summarize TotalBytesSent = sum(SentBytes) by DeviceName, RemoteIP, bin(TimeGenerated, 1h)
| where TotalBytesSent > 50000000  // > 50 MB in 1 hour
| order by TotalBytesSent desc
```

**What it does:** Flags devices sending unusually large amounts of data externally  potential data exfiltration indicator.

---

### 4. Account Created Outside Business Hours

```kql
SecurityEvent
| where EventID == 4720  // User account created
| where hourofday(TimeGenerated) < 8 or hourofday(TimeGenerated) > 18
| project TimeGenerated, TargetUserName, SubjectUserName, Computer
```

**What it does:** New accounts created at night or weekends should be reviewed  could indicate a persistence mechanism.

---

## Study Resources
- [SC-200 learning path  Microsoft Learn](https://learn.microsoft.com/en-us/certifications/exams/sc-200)
- Microsoft Sentinel documentation
- KQL quick reference: https://aka.ms/kql-quick-reference
