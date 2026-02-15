"""
Phoenix DFIR - MITRE ATT&CK Mapping
Mapping des evenements Windows et indicateurs vers les techniques ATT&CK
"""

# Mapping Event ID Windows -> MITRE ATT&CK
EVENT_TO_ATTACK = {
    # Initial Access
    4624: [{"tactic": "Initial Access", "technique": "T1078", "name": "Valid Accounts"}],
    4625: [{"tactic": "Credential Access", "technique": "T1110", "name": "Brute Force"}],

    # Execution
    4688: [{"tactic": "Execution", "technique": "T1059", "name": "Command and Scripting Interpreter"}],
    1: [{"tactic": "Execution", "technique": "T1059", "name": "Command and Scripting Interpreter"}],

    # Persistence
    4697: [{"tactic": "Persistence", "technique": "T1543.003", "name": "Windows Service"}],
    4698: [{"tactic": "Persistence", "technique": "T1053.005", "name": "Scheduled Task"}],
    7045: [{"tactic": "Persistence", "technique": "T1543.003", "name": "Windows Service"}],
    13: [{"tactic": "Persistence", "technique": "T1547.001", "name": "Registry Run Keys"}],

    # Privilege Escalation
    4672: [{"tactic": "Privilege Escalation", "technique": "T1078", "name": "Valid Accounts"}],
    4648: [{"tactic": "Privilege Escalation", "technique": "T1134", "name": "Access Token Manipulation"}],

    # Defense Evasion
    1102: [{"tactic": "Defense Evasion", "technique": "T1070.001", "name": "Clear Windows Event Logs"}],
    4689: [{"tactic": "Defense Evasion", "technique": "T1070", "name": "Indicator Removal"}],

    # Credential Access
    4771: [{"tactic": "Credential Access", "technique": "T1558", "name": "Steal or Forge Kerberos Tickets"}],
    4768: [{"tactic": "Credential Access", "technique": "T1558.003", "name": "Kerberoasting"}],

    # Discovery
    4799: [{"tactic": "Discovery", "technique": "T1069", "name": "Permission Groups Discovery"}],

    # Lateral Movement
    4778: [{"tactic": "Lateral Movement", "technique": "T1021", "name": "Remote Services"}],

    # Collection
    4663: [{"tactic": "Collection", "technique": "T1005", "name": "Data from Local System"}],

    # Exfiltration
    3: [{"tactic": "Exfiltration", "technique": "T1041", "name": "Exfiltration Over C2 Channel"}],

    # Impact
    4720: [{"tactic": "Impact", "technique": "T1136", "name": "Create Account"}],
    4726: [{"tactic": "Impact", "technique": "T1531", "name": "Account Access Removal"}],
}

# Mapping IoC type -> possible ATT&CK techniques
IOC_TO_ATTACK = {
    'ip': [{"tactic": "Command and Control", "technique": "T1071", "name": "Application Layer Protocol"}],
    'domain': [{"tactic": "Command and Control", "technique": "T1071.001", "name": "Web Protocols"}],
    'url': [{"tactic": "Command and Control", "technique": "T1071.001", "name": "Web Protocols"}],
    'hash_md5': [{"tactic": "Execution", "technique": "T1204", "name": "User Execution"}],
    'hash_sha1': [{"tactic": "Execution", "technique": "T1204", "name": "User Execution"}],
    'hash_sha256': [{"tactic": "Execution", "technique": "T1204", "name": "User Execution"}],
    'email': [{"tactic": "Initial Access", "technique": "T1566", "name": "Phishing"}],
    'registry_key': [{"tactic": "Persistence", "technique": "T1547.001", "name": "Registry Run Keys"}],
    'cve': [{"tactic": "Initial Access", "technique": "T1190", "name": "Exploit Public-Facing Application"}],
}


def get_attack_for_event(event_id):
    """Retourner les techniques ATT&CK pour un Event ID"""
    return EVENT_TO_ATTACK.get(event_id, [])


def get_attack_for_ioc(ioc_type):
    """Retourner les techniques ATT&CK pour un type d'IoC"""
    return IOC_TO_ATTACK.get(ioc_type, [])


def enrich_events_with_attack(events):
    """Enrichir une liste d'evenements avec les mappings ATT&CK"""
    for event in events:
        event_id = event.get('event_id')
        if event_id:
            event['mitre_attack'] = get_attack_for_event(event_id)
    return events


def get_attack_summary(event_ids):
    """Generer un resume des tactiques ATT&CK detectees"""
    tactics = {}
    for eid in event_ids:
        for mapping in get_attack_for_event(eid):
            tactic = mapping['tactic']
            if tactic not in tactics:
                tactics[tactic] = []
            tech = f"{mapping['technique']}: {mapping['name']}"
            if tech not in tactics[tactic]:
                tactics[tactic].append(tech)
    return tactics
