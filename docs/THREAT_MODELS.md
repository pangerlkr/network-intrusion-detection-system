# Threat Models & Attack Scenarios

This document outlines the attack vectors, threat models, and adversary profiles that the NIDS is designed to detect and mitigate.

## MITRE ATT&CK Framework

The NIDS maps detection capabilities against the MITRE ATT&CK Matrix for Enterprise, specifically targeting:

### Reconnaissance (TA0043)
- **T1592 - Gather Victim Host Information**
  - Detection: Port scanning, banner grabbing detection
  - Mitigation: Alert on unusual scanning patterns

### Initial Access (TA0001)
- **T1200 - Hardware Additions**
  - Detection: Unusual network interfaces, device enumeration
  - Mitigation: Monitor for network discovery traffic

### Command & Control (TA0011)
- **T1071 - Application Layer Protocol**
  - Detection: Abnormal HTTP/HTTPS traffic patterns
  - Mitigation: Deep packet inspection, payload analysis

## Common Attacks Detected

### 1. DDoS Attacks

#### SYN Flood
- **Signature**: Large number of SYN packets from unique sources
- **Detection Method**: Rule-based + Statistical anomaly detection
- **Alert Threshold**: > 1000 SYN packets/second
- **Recommended Action**: Enable SYN cookies, rate limiting

#### UDP Flood
- **Signature**: High volume of UDP packets to random ports
- **Detection Method**: Volume-based anomaly detection
- **Alert Threshold**: > 5MB/s from single source

### 2. Brute Force Attacks

#### SSH Brute Force
- **Signature**: Multiple failed authentication attempts on port 22
- **Detection Method**: Behavioral pattern matching
- **Alert Threshold**: > 5 failed attempts per minute from single IP
- **Recommended Action**: Implement fail2ban, SSH key authentication

#### Web Application Brute Force
- **Signature**: Multiple 401/403 responses to same endpoint
- **Detection Method**: HTTP response code analysis
- **Alert Threshold**: > 10 failed login attempts per minute

### 3. Injection Attacks

#### SQL Injection
- **Signature**: SQL keywords in URL parameters (SELECT, UNION, DROP)
- **Detection Method**: Payload analysis with regex patterns
- **Alert Severity**: HIGH
- **Recommended Action**: WAF rules, input validation

#### Command Injection
- **Signature**: Shell metacharacters in HTTP requests (`;|&>`)
- **Detection Method**: Payload analysis
- **Alert Severity**: CRITICAL

### 4. Network Reconnaissance

#### Port Scanning
- **Signature**: Sequential port connections from single source
- **Detection Method**: Connection behavior analysis
- **Alert Threshold**: > 50 unique ports in 60 seconds
- **Recommended Action**: Block source IP, firewall rules

#### Network Mapping (Traceroute, Nmap)
- **Signature**: ICMP TTL exceeded messages, specific packet patterns
- **Detection Method**: Protocol-specific pattern matching
- **Alert Severity**: MEDIUM (reconnaissance phase)

### 5. Malware-Related Traffic

#### Botnet Command & Control (C2)
- **Signature**: Unusual DNS queries, beaconing patterns
- **Detection Method**: Statistical analysis of traffic patterns
- **Alert Threshold**: Regular connections to same external IP/domain
- **Recommended Action**: Block C2 domains, isolate infected host

#### Data Exfiltration
- **Signature**: Large data transfers to external IPs
- **Detection Method**: Volume-based anomaly detection
- **Alert Threshold**: > 100MB transfer to new external IP

## Zero-Day and Advanced Threats

The NIDS uses machine learning models (Isolation Forest, LSTM) to detect:

- **Unknown Attack Patterns**: Behavioral deviations from baseline
- **Advanced Persistent Threats (APT)**: Multi-stage attack chains
- **Polymorphic Malware**: Signature-less detection via behavior

## Tuning & False Positive Reduction

1. **Whitelist Legitimate Traffic**: Common admin tools, backup systems
2. **Baseline Establishment**: Profile normal network behavior
3. **Sensitivity Adjustment**: Tune detection thresholds per environment
4. **Correlation Rules**: Reduce alerts by grouping related events

---

**Last Updated**: January 2026  
**Threat Model Version**: 1.0.0  
**MITRE ATT&CK Alignment**: v12.0
