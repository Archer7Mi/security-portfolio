# Case Study: Phishing Email Leading to Credential Theft Attempt

**Date:** 2026-01-20  
**Type:** Phishing / Social Engineering  
**Severity:** High  
**Outcome:** Contained  no credentials confirmed stolen

---

## 1. Summary

A user in the finance department reported receiving a suspicious email appearing to come from the company's IT helpdesk, requesting they "verify their account" via a link. The link pointed to a fake Office 365 login page hosted on a typosquatted domain.

---

## 2. Initial Alert

- User forwarded the phishing email to IT
- Email gateway flagged the sending domain as newly registered (3 days old)
- No automatic filter triggered because the domain had not yet appeared on threat intel feeds

---

## 3. Investigation Steps

### Step 1  Analyse the email headers
```
From: helpdesk@it-support-notices[.]com    not the real domain
Reply-To: helpdesk@it-support-notices[.]com
X-Originating-IP: 185.220.101.47
```
The sending domain `it-support-notices[.]com` was registered 3 days prior to the email. Legitimate IT communications come from the company's own domain.

### Step 2  Examine the link
```
hxxps://office365-accountverify[.]com/login
```
WHOIS lookup: registered 4 days ago, registrar privacy protection applied, hosted on a shared hosting provider in Eastern Europe.

VirusTotal: 2/90 vendors flagged at time of investigation (low detection  new domain).

### Step 3  Check if the link was clicked
Email gateway logs showed the link was clicked by the original recipient before they forwarded the email to IT.

```
Log: User jndeda@company.com clicked URL at 10:14:32 UTC
```

### Step 4  Check for credential submission
Authentication logs for `jndeda@company.com` showed no new logins from unexpected IPs in the 2 hours following the click. No MFA prompts from unrecognised devices.

---

## 4. Conclusion

The user clicked the link but there is no evidence credentials were submitted or that an external login occurred. The phishing page may have been unavailable at the time of the click, or the user navigated away.

**No confirmed compromise.**

---

## 5. Actions Taken

- Blocked `office365-accountverify[.]com` at the DNS/proxy layer
- Blocked sending domain `it-support-notices[.]com` in email gateway
- Notified the affected user and ran a targeted awareness reminder
- Submitted IOCs (domains, sending IP) to threat intel platform

## 6. Lessons Learned

- Newly registered domains are a strong phishing indicator  tuning email gateway to flag/quarantine emails from domains <30 days old would have caught this
- The low VirusTotal detection rate shows reliance on AV-style feeds alone is insufficient for fresh phishing infrastructure
