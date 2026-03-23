# Hybrid Attack Detection using Splunk (SOC Simulation)

## Overview

This project simulates a real-world cyber attack scenario and demonstrates how a Security Operations Center (SOC) detects and analyzes malicious activity using Windows logs and Splunk.

The lab includes:
- Brute force attack simulation
- PowerShell-based post-compromise activity
- Log collection and validation
- Detection engineering in Splunk
- Event correlation across multiple log sources

---

## Environment Setup

- Windows 10 Target Machine
- Kali Linux Attacker Machine
- Sysmon installed and configured
- PowerShell Script Block Logging enabled
- Splunk Enterprise for log analysis

![PowerShell Logging](01_setup/01_powershell_logging_enabled.png)
![Sysmon Running](01_setup/02_sysmon_running.png)

---

## Attack Simulation

The attacker performed multiple post-compromise activities:

1. Encoded PowerShell execution (stealth technique)
2. Command execution for reconnaissance
3. Attempted file download using PowerShell
4. Process spawning (cmd.exe, notepad.exe)

![Encoded Command](02_attack_simulation/03_encoded_command_generation.png)
![Execution](02_attack_simulation/04_encoded_command_execution.png)
![Download Attempt](02_attack_simulation/05_download_attempt.png)
![Process Spawn](02_attack_simulation/06_process_spawn.png)

---

## Log Validation

Logs were validated using Event Viewer and Sysmon:

- Event ID 4104 → PowerShell script execution
- Sysmon Event ID 1 → Process creation tracking

![Event Viewer 4104](03_log_validation/08_eventviewer_4104.png)
![Sysmon Encoded](03_log_validation/09_sysmon_encoded_powershell.png)
![Process Chain](03_log_validation/10_sysmon_cmd_parent_powershell.png)

---

## Detection Engineering (Splunk)

Detection rules were created to identify suspicious activity:

1. Encoded PowerShell detection
2. Suspicious keyword detection (Invoke-WebRequest, DownloadString)
3. Process execution monitoring

![Encoded Detection](04_splunk_detection/11_splunk_encoded_detection.png)
![Keyword Detection](04_splunk_detection/12_splunk_keyword_detection.png)
![Process Chain](04_splunk_detection/13_splunk_process_chain.png)

---

## Correlation Analysis

Multiple logs were correlated to understand the full attack chain:

- Brute force attempt
- PowerShell execution
- Process creation

![Correlation](05_correlation/15_splunk_correlation_timeline.png)

---

## Analysis & Findings

The attacker used encoded PowerShell commands to evade detection and executed reconnaissance commands on the system.

The failed download attempt indicates an attempt to retrieve external payloads.

Process creation logs confirm PowerShell spawning additional processes, which is a strong indicator of post-exploitation activity.

This behavior aligns with MITRE ATT&CK techniques such as:
- T1059.001 (PowerShell)
- T1105 (Ingress Tool Transfer)

---

## Conclusion

This project demonstrates how multiple data sources can be used to detect, investigate, and correlate malicious activity in a SOC environment.

It highlights the importance of:
- PowerShell logging
- Process monitoring
- SIEM-based detection
