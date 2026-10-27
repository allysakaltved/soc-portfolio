# Alert Triage with Splunk

This project documents my experience investigating security alerts using Splunk in a simulated SOC environment. Each investigation includes the initial alert, the searches I performed, what I found, and the next steps I would take as a security analyst.

---

## Alert 1: Brute Force Activity Alert on a Linux Host

### Step 1: Receiving the Alert

![Initial Alert](images/splunk_alert_1.png)

After receiving the alert, I first reviewed the information provided to determine what I knew and what needed further investigation.

- **Alert Name:** Brute Force Activity Detection — Indicates that suspicious login activity may have been detected.
- **Time:** September 17, 2025, at 9:00:21 AM — This falls within typical business hours, but that doesn't necessarily mean the activity is legitimate.
- **Target Host:** `tryhackme-2404` — Identifies the Linux system being targeted. The hostname alone doesn't tell me much about the system or its importance.
- **Source IP:** `10.10.242.248` — This is a private IP address, which could indicate activity originating from within the network. I would need to verify where this device is located.

**Next Steps:** The alert alone doesn't confirm a brute-force attack. I'll need to review the authentication logs to understand what happened and determine whether anyone successfully accessed the system.

### Step 2: Investigating the Alert

I started by searching the SIEM for successful logins, failed logins, and attempts involving invalid usernames.

**Splunk Query 1:**

```spl
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| search "Accepted password for" OR "Failed password for" OR "Invalid user"
| sort + _time
```

This searches the `linux-alert` index for Linux security events containing the suspicious IP address. It filters the results to show successful logins, failed logins, and invalid username attempts, then arranges them from oldest to newest.

![Initial Search Results](images/splunk_initial_search_results_1.png)

**What I Found:**

- **543 events:** A large number of matching events worth investigating further.
- **Invalid user:** Login attempts were made using usernames that did not exist on the system.
- **Failed password:** Some login attempts were unsuccessful.

These results show suspicious authentication activity, but I still need to determine how frequently each account was targeted.

#### Identifying Targeted Accounts

**Splunk Query 2:**

```spl
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| rex field=_raw "^\d{4}-\d{2}-\d{2}T[^\s]+\s+(?<log_hostname>\S+)"
| rex field=_raw "sshd\[\d+\]:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval process="sshd"
| stats count values(src_ip) as src_ip values(log_hostname) as hostname values(process) as process by username
```

![Login Attempts by Username](images/splunk_query_2.png)

This query takes information from SSH login logs and groups the results by username. It counts the matching login events for each account so I can identify which accounts were targeted most frequently.

**What I Found:**

- Four usernames appeared in the results.
- `john.smith` had **503 matching authentication events**, significantly more than the other accounts.
- All four usernames were associated with the same source IP, `10.10.242.248`.

The high number of login attempts against `john.smith` is strong evidence of brute-force activity. My next step is to determine whether any of these attempts were successful.

#### Checking for Successful Logins

**Splunk Query 3:**

```spl
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| rex field=_raw "^\d{4}-\d{2}-\d{2}T[^\s]+\s+(?<log_hostname>\S+)"
| rex field=_raw "sshd\[\d+\]:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval process="sshd"
| stats count values(action) values(src_ip) as src_ip values(log_hostname) as hostname values(process) as process by username
```

![Authentication Results](images/splunk_query_3.png)

This query is similar to the previous one, but it also shows whether each account had failed or accepted login attempts.

**What I Found:**

The results show both `Failed` and `Accepted` authentication events for `john.smith`. This confirms that at least one login attempt from the suspicious IP address was successful.

To see the actual successful login events, I removed the `stats` command and filtered the results to show only accepted logins.

**Splunk Query 4 — Successful Logins:**

```spl
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| rex field=_raw "^\d{4}-\d{2}-\d{2}T[^\s]+\s+(?<log_hostname>\S+)"
| rex field=_raw "sshd\[\d+\]:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval process="sshd"
| search action="Accepted"
```

![Successful Login Events](images/splunk_query_4.png)

Removing `stats` allows me to view the original log events instead of a summary. Filtering for `Accepted` shows the successful SSH logins.

**What I Found:**

The logs show three successful SSH authentications to `john.smith` from `10.10.242.248`, including one at approximately **9:06 AM**.

Based on the repeated authentication attempts and successful logins, I would classify this alert as a **true positive** and escalate it for further investigation.

### Step 3: Investigating Activity After the Successful Login

Now that I've confirmed successful authentication, I want to understand what happened afterward.

I searched for activity involving `john.smith` beginning around the time of the first successful login.

**Splunk Query 5:**

```spl
index="linux-alert" "john.smith"
| where _time >= strptime("2025-09-17 09:06:00", "%Y-%m-%d %H:%M:%S")
| sort + _time
```

This searches for logs mentioning `john.smith` after the specified time and displays them chronologically. It helps me follow the account's recorded activity after the successful login.

![Post-Login Activity](images/splunk_query_5.png)

**What I Found:**

- **Privilege escalation:** The logs show `john.smith` using `sudo` to execute `/usr/bin/su` as `root`, followed by a root session being opened. This indicates that the account gained elevated privileges.
- **New account creation:** The logs show a command to create an account named `system-utm`, followed by an entry showing that account in the system's user group information.
- **Possible persistence:** Creating an additional account after gaining elevated privileges could provide a way to maintain access to the system. This would need further investigation to confirm how the account was configured and whether it was used.

### Final Findings and Assessment

My investigation identified evidence consistent with a successful SSH brute-force attack against the Linux host `tryhackme-2404`.

The suspicious source IP generated numerous authentication events, successfully logged in as `john.smith`, and was followed by activity showing elevated root privileges and creation of the `system-utm` account.

**Alert Classification:** True Positive

**Recommended Next Steps:** I would escalate this incident to the appropriate security team for containment and further investigation. This would include reviewing the suspicious source device, securing the affected accounts, investigating the newly created account, and checking for any additional unauthorized activity.

### Skills Demonstrated

- Security alert triage
- Splunk SIEM searching and log analysis
- SSH authentication investigation
- Brute-force attack identification
- Privilege escalation investigation
- Incident documentation and escalation
