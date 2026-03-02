# Splunk SPL Detections

Detection queries written in SPL (Search Processing Language) for Splunk. Testing against sample log data in a Splunk free trial instance.

---

## 1. SSH Brute Force Detection

```spl
index=linux_logs sourcetype=syslog "Failed password"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as attempts by src_ip
| where attempts > 20
| sort -attempts
```

**Logic:** Count failed SSH password attempts per source IP. Flag anything with more than 20 attempts.

---

## 2. Windows Failed Logon Spike

```spl
index=windows EventCode=4625
| stats count as failures by src_ip, user
| where failures > 15
| table user, src_ip, failures
```

**Logic:** Windows Event ID 4625 is a failed logon. More than 15 from the same user/IP combination is suspicious.

---

## 3. New Local Admin Account Created

```spl
index=windows EventCode=4720 OR EventCode=4732
| eval event_type=case(EventCode==4720, "Account Created", EventCode==4732, "Added to Group")
| table _time, event_type, user, src_user, Computer
```

**Logic:** Alert on account creation (4720) and any account being added to a privileged group (4732).

---

## 4. Large Outbound Data Transfer

```spl
index=network sourcetype=firewall action=allowed direction=outbound
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip
| eval mb = round(total_bytes/1048576, 2)
| where mb > 100
| sort -mb
```

**Logic:** Calculates outbound traffic by source/destination pair. More than 100 MB flagged for review.

---

## Notes
- These queries are written for educational purposes against sample data
- Real deployment would require index names and field names adjusted to match the actual environment
