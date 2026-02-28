# DNS Threat Detection Guide

## What DNS Expert Monitor Detects

### 1. DNS Tunneling
**Description**: Technique to bypass firewalls by encapsulating data within DNS queries.

**Indicators**:
- High entropy domains (>4.5)
- Excessively long subdomains (>50 characters)
- Base64/Hexadecimal patterns in domain names
- Unusual record types (TXT, NULL, KEY)

**Detection Example**:
🚨 ALERT: High entropy (4.62) in domain: 23pzgde427i3ln7qmkdr986h4snnkt.example.com

### 2. DNS Poisoning / Cache Poisoning
**Description**: Injection of fake DNS records into cache.

**Indicators**:
- Abnormally low TTL (<30 seconds)
- Multiple different responses for the same query
- Responses from unauthorized servers

**Detection Example**:
⚠️ WARNING: Abnormally low TTL (5s) for main.vscode-cdn.net


### 3. DNS Amplification Attacks
**Description**: DDoS attacks using DNS servers to amplify traffic.

**Indicators**:
- High response/query ratio (>10:1)
- Anomalous query rates (>100 QPS)
- Excessive ANY type queries

**Detection Example**:
⚠️ WARNING: High query rate (924.2 QPS) from 192.168.111.128

### 4. NXDOMAIN Attacks
**Description**: Flooding with NXDOMAIN responses to overwhelm servers.

**Indicators**:
- High percentage of NXDOMAIN responses (>30%)
- Elevated NXDOMAIN rate per minute (>100)
- Randomly generated subdomains

---

## Recommended Configuration

### For Corporate Networks:
```
detectors:
  dns_tunneling:
    entropy_threshold: 4.3      # More sensitive
    max_subdomain_length: 40    # More restrictive
  
  poisoning_detector:
    min_ttl_for_alert: 60       # Minimum acceptable TTL
  
  amplification_detector:
    max_queries_per_second: 50  # Lower threshold
  
  nxdomain_attack:
    nxdomain_percentage_threshold: 20  # More sensitive
```
### For ISPs/Carriers:
```
detectors:
  amplification_detector:
    min_amplification_ratio: 5   # More sensitive to amplification
    max_queries_per_second: 1000 # Higher tolerance
  
  nxdomain_attack:
    nxdomain_per_minute_threshold: 500 # Carrier-scale
```

## Recommended Mitigation
## For DNS Tunneling:
- Implement DNS filtering with allowlists
- Limit maximum domain name length
- Monitor unusual record types

## For DNS Poisoning:
- Use DNSSEC for cryptographic validation
- Configure appropriate minimum TTLs
- Restrict authorized DNS servers

## For DNS Amplification DDoS:
- Rate limiting on recursive DNS servers
- Disable or restrict ANY type queries
- Implement Response Rate Limiting (RRL)

# Case Studies

## Case 1: Data Exfiltration
- Scenario: Employee exfiltrates corporate data via DNS tunneling.
- Detection: High entropy and Base64 pattern alerts.
- Action: Investigate source IP, block suspicious domains.

## Case 2: DDoS Attack on Infrastructure
- Scenario: Amplification attack against web servers.
- Detection: High ratio and query rate alerts.
- Action: Implement rate limiting, contact ISP.

## Case 3: Cache Poisoning
- Scenario: Attacker redirects traffic to malicious servers.
- Detection: Low TTL and multiple response alerts.
- Action: Validate DNSSEC, purge DNS cache.

# Threshold Reference Table

| Threat | Parameter | Normal Range |	Suspicious | Critical |
|--------|-----------|--------------|------------|----------|
| Tunneling |	Domain Entropy | < 3.5 | 3.5 - 4.5 |	> 4.5 |
| Tunneling |	Subdomain Length | < 30 |	30 - 50 |	> 50 |
| Poisoning |	TTL (seconds) |	> 300 |	30 - 300 |	< 30 |
| Amplification |	Query Rate (QPS) |	< 20 | 20 - 100 |	> 100 |
| Amplification |	Response Ratio | < 3x |	3x - 10x | > 10x |
| NXDOMAIN | Error Rate |	< 5% | 5% - 30% |	> 30% |

# Additional Resources

- DNSSEC: https://www.cloudflare.com/dns/dnssec/
- Response Rate Limiting: RFC 8020
- DNS Tunneling Detection: IETF Draft

This guide is part of DNS Expert Monitor documentation. For more information, visit the main repository.