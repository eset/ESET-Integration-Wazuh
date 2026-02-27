# ESET Protect On-Prem Syslog Integration for Wazuh

This directory contains Wazuh decoders and rules for ingesting ESET Protect On-Premise syslog JSON output.

## Background

The existing `eset_local_rules.xml` is designed for the ESET Cloud API integration script, which wraps events in a custom JSON structure with fields like `eset.category`, `eset.severityLevel`, and `eset.edrRuleUuid`.

ESET Protect On-Premise has a built-in Syslog export feature that sends events directly over syslog in RFC 5424 format with a JSON payload. The JSON schema differs from the API output — it uses root-level fields like `event_type`, `severity`, `threat_name`, etc. as documented at:
https://help.eset.com/protect_admin/12.1/en-US/events-exported-to-json-format.html

This integration provides native Wazuh support for these syslog events.

## Files

| File | Wazuh Location | Description |
|------|---------------|-------------|
| `eset_syslog_decoder.xml` | `/var/ossec/etc/decoders/local_decoder.xml` | Custom decoder to handle RFC 5424 syslog with UTF-8 BOM |
| `eset_syslog_rules.xml` | `/var/ossec/etc/rules/eset_syslog_rules.xml` | 1,263 rules covering all ESET event types with MITRE ATT&CK mappings |

## Supported Event Types

| Event Type | Rule ID | Description |
|-----------|---------|-------------|
| `Threat_Event` | 440020 | Antivirus detections |
| `FirewallAggregated_Event` | 440030 | Firewall detections |
| `HipsAggregated_Event` | 440040 | HIPS detections |
| `EnterpriseInspectorAlert_Event` | 440050 | ESET Inspect / EDR alerts |
| `BlockedFiles_Event` | 440055 | Blocked files |
| `Audit_Event` | 440060 | Console audit log |
| `FilteredWebsites_Event` | 440080 | Web protection detections |

## Severity Escalation

| Severity | Rule ID | Wazuh Level |
|----------|---------|-------------|
| Information / Notice | (category rule) | 3 |
| Warning | 440120 | 7 |
| Error | 440121 | 7 |
| Critical | 440130 | 12 |
| Fatal | 440131 | 15 |

## EDR / ESET Inspect Rules

All 1,247 EDR rules from `eset_local_rules.xml` have been mapped to match the `rulename` field in `EnterpriseInspectorAlert_Event` syslog output. Original rule IDs (420140-432600), severity levels, and MITRE ATT&CK technique IDs are preserved.

## ESET Protect On-Prem Configuration

1. Navigate to **More > Settings > Advanced Settings > Syslog server**
2. Enable **Use Syslog server**
3. Enter your Wazuh Manager IP and port (e.g., 514)
4. Set **Exported logs format** to **JSON**
5. Select the log categories you want to export

## Wazuh Configuration

### 1. Decoder

Append the contents of `eset_syslog_decoder.xml` to `/var/ossec/etc/decoders/local_decoder.xml`, or place it as a separate file in `/var/ossec/etc/decoders/`.

The decoder handles two challenges:
- ESET sends RFC 5424 syslog, but Wazuh expects RFC 3164 — so `program_name` is not extracted correctly by the default pre-decoder

### 2. Rules

Copy `eset_syslog_rules.xml` to `/var/ossec/etc/rules/`.

### 3. Syslog Listener

Add a syslog listener to `/var/ossec/etc/ossec.conf`:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>YOUR_ESET_SERVER_IP</allowed-ips>
</remote>
```

### 4. Restart

Restart the Wazuh Manager to apply changes.

## Verification

Use `wazuh-logtest` or the Wazuh UI Ruleset Test tool to verify. Paste a raw ESET syslog message (including the RFC 5424 header):

```
<14>1 2026-02-27T16:25:37.704Z YOURHOST ERAServer 3432 - - {"event_type":"Threat_Event","ipv4":"192.168.1.100","hostname":"workstation01","severity":"Warning","threat_name":"Eicar","action_taken":"Connection terminated","threat_handled":true}
```

Phase 3 should show the matching rule firing.
