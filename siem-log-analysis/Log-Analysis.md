
# Case Study: SIEM Log Analysis & Cyber Triage (Linux Privilege Escalation)

## Overview
This case study documents a simulated Security Operations Center (SOC) investigation involving SIEM log analysis and incident triage. The objective was to analyze host-based logs, identify suspicious activity, correlate events across systems, and assess whether observed behavior constituted a confirmed security incident.

The investigation focused on Linux-based privilege escalation activity detected through log analysis and security alerts.

## Tools & Technologies
Microsoft Sentinel (SIEM log analysis)
Microsoft Defender (Incident investigation & correlation)
Linux host logs (authentication, kernel, sudo activity)

## Step 1: Initial SIEM Log Access
Accessed Microsoft Sentinel logs and confirmed log ingestion from Linux hosts within the environment.
<img width="959" height="455" alt="SOC_2" src="https://github.com/user-attachments/assets/f555edee-c8c3-4540-a4dc-6f345dc91e83" />


## Step 2: Broad Log Review
Reviewed aggregated Syslog data to understand baseline activity, including authentication events, cron jobs, sudo usage, and kernel messages.
<img width="956" height="457" alt="SOC_3" src="https://github.com/user-attachments/assets/68297b6d-564e-4d72-9455-fd25a2317fb1" />


## Step 3 & 4: Identifying Suspicious Indicators & Incident Discovery in Defender
Observed high-risk log entries such as:
`kernel: audit` events
`insert_module` activity
sudo and authentication anomalies

These indicators suggested potential privilege escalation behavior.
Reviewed correlated security incidents generated from SIEM analytics within Microsoft Defender, identifying multiple Linux privilege escalation detections.
<img width="959" height="459" alt="SOC_4" src="https://github.com/user-attachments/assets/2b3cc48d-9959-44f5-be58-7e572627c718" />


## Step 5: Kernel Module Insertion Incident
Investigated a high-severity incident involving kernel module insertion across multiple Linux hosts, indicating potential root-level compromise.
<img width="957" height="458" alt="SOC_8" src="https://github.com/user-attachments/assets/4f304c6a-42ad-457f-8b66-0f3269e22186" />


## Step 6: Polkit Privilege Escalation Attempt
Reviewed a separate incident related to a Polkit exploit attempt, confirming detection of a known Linux privilege escalation vector.
<img width="957" height="458" alt="SOC_5" src="https://github.com/user-attachments/assets/4a47931c-1fd3-43c1-8ad8-92a5523301e9" />


## Step 7: Sudo Shadow File Access
Analyzed an incident indicating unauthorized access to `/etc/shadow`, a critical credential store, signaling potential credential compromise.
<img width="958" height="458" alt="SOC_6" src="https://github.com/user-attachments/assets/a617b964-e963-40b9-b6be-ccf225f8f6ef" />



## Step 8: User Added to Sudo Group
Investigated activity showing unauthorized users being added to the sudo group, demonstrating persistence and privilege escalation techniques.
<img width="958" height="458" alt="SOC_7" src="https://github.com/user-attachments/assets/1f0d0388-193e-4278-86ea-60c17abd3ddc" />


## Step 9: Verify Commands Executed on Breached Server
Investigated commands pushed by "alic" account, showing a copy of the shadow directory.
<img width="959" height="455" alt="SOC_9" src="https://github.com/user-attachments/assets/f4112061-17db-488e-b2f9-c109cf5be543" />


## Findings & Assessment
Multiple Linux hosts exhibited privilege escalation behavior.
Indicators aligned with known techniques including kernel module insertion, Polkit exploitation, and sudo abuse.
Activity was correlated across logs and alerts, confirming a legitimate security incident rather than isolated noise.

## Skills Demonstrated
SIEM log analysis and filtering
Security event triage and prioritization
Incident investigation using modern SOC tooling
Log correlation across multiple hosts
Understanding of Linux privilege escalation techniques
Incident documentation and analysis

---

## Notes
*This investigation was conducted in a simulated lab environment for training and professional development purposes.*
