"""
Phoenix DFIR - Sigma Rule Connector
Conversion et application de regles Sigma pour la detection
"""

import os
import json
from integrations.base import BaseConnector
from integrations import registry


@registry.register
class SigmaConnector(BaseConnector):
    CONNECTOR_ID = 'sigma'
    CONNECTOR_NAME = 'Sigma'
    CONNECTOR_DESCRIPTION = 'Regles de detection generiques - Compatible SIEM universel'
    CONNECTOR_ICON = 'file-code'
    CONNECTOR_URL = 'https://sigmahq.io'
    CONNECTOR_CATEGORY = 'rule_engine'

    CONFIG_SCHEMA = [
        {'key': 'rules_path', 'label': 'Dossier des regles Sigma', 'type': 'text', 'required': False, 'placeholder': '/path/to/sigma/rules'},
    ]

    # Regles Sigma integrees - couvrent MITRE TA0001..TA0011
    BUILTIN_RULES = [
        # === Credential Access (TA0006) ===
        {
            'id': 'phoenix-brute-force',
            'title': 'Brute Force Detection',
            'description': 'Tentatives massives de logon echouees (Event ID 4625)',
            'level': 'high',
            'tactic': 'credential_access', 'technique': 'T1110',
            'logsource': {'product': 'windows', 'service': 'security'},
            'detection': {'event_id': [4625], 'threshold': 5},
        },
        {
            'id': 'phoenix-pass-the-hash',
            'title': 'Possible Pass-the-Hash',
            'description': 'Logon type 9 (newcredentials) - signe de PtH',
            'level': 'high',
            'tactic': 'lateral_movement', 'technique': 'T1550.002',
            'logsource': {'product': 'windows', 'service': 'security'},
            'detection': {'event_id': [4624], 'logon_type': 9},
        },
        {
            'id': 'phoenix-kerberoasting',
            'title': 'Possible Kerberoasting',
            'description': 'Demande de ticket TGS avec encryption RC4 (Event 4769)',
            'level': 'high',
            'tactic': 'credential_access', 'technique': 'T1558.003',
            'logsource': {'product': 'windows', 'service': 'security'},
            'detection': {'event_id': [4769], 'ticket_encryption': '0x17'},
        },
        {
            'id': 'phoenix-ntds-extract',
            'title': 'NTDS.dit Access Attempt',
            'description': 'Acces au fichier NTDS.dit (extraction credentials AD)',
            'level': 'critical',
            'tactic': 'credential_access', 'technique': 'T1003.003',
            'logsource': {'product': 'windows', 'service': 'security'},
            'detection': {'event_id': [4663], 'object_name_contains': 'ntds.dit'},
        },
        {
            'id': 'phoenix-lsass-access',
            'title': 'LSASS Memory Access',
            'description': 'Acces a la memoire LSASS (Mimikatz-like)',
            'level': 'critical',
            'tactic': 'credential_access', 'technique': 'T1003.001',
            'logsource': {'product': 'windows', 'service': 'sysmon'},
            'detection': {'event_id': [10], 'target_image_contains': 'lsass.exe'},
        },

        # === Defense Evasion (TA0005) ===
        {
            'id': 'phoenix-log-clearing',
            'title': 'Security Log Cleared',
            'description': 'Suppression du journal de securite (Event 1102)',
            'level': 'critical',
            'tactic': 'defense_evasion', 'technique': 'T1070.001',
            'logsource': {'product': 'windows', 'service': 'security'},
            'detection': {'event_id': [1102]},
        },
        {
            'id': 'phoenix-system-log-cleared',
            'title': 'System Log Cleared',
            'description': 'Suppression du journal systeme (Event 104)',
            'level': 'high',
            'tactic': 'defense_evasion', 'technique': 'T1070.001',
            'logsource': {'product': 'windows', 'service': 'system'},
            'detection': {'event_id': [104]},
        },
        {
            'id': 'phoenix-defender-disable',
            'title': 'Windows Defender Disabled',
            'description': 'Desactivation de Microsoft Defender (Event 5001/5004)',
            'level': 'high',
            'tactic': 'defense_evasion', 'technique': 'T1562.001',
            'logsource': {'product': 'windows', 'service': 'defender'},
            'detection': {'event_id': [5001, 5004, 5007]},
        },
        {
            'id': 'phoenix-firewall-disable',
            'title': 'Windows Firewall Disabled',
            'description': 'Desactivation du pare-feu (Event 2003)',
            'level': 'high',
            'tactic': 'defense_evasion', 'technique': 'T1562.004',
            'logsource': {'product': 'windows', 'service': 'firewall'},
            'detection': {'event_id': [2003]},
        },

        # === Persistence (TA0003) ===
        {
            'id': 'phoenix-new-service',
            'title': 'New Service Installed',
            'description': 'Installation de service (Event 7045)',
            'level': 'medium',
            'tactic': 'persistence', 'technique': 'T1543.003',
            'logsource': {'product': 'windows', 'service': 'system'},
            'detection': {'event_id': [7045]},
        },
        {
            'id': 'phoenix-scheduled-task',
            'title': 'Scheduled Task Created',
            'description': 'Creation de tache planifiee (Event 4698)',
            'level': 'medium',
            'tactic': 'persistence', 'technique': 'T1053.005',
            'logsource': {'product': 'windows', 'service': 'security'},
            'detection': {'event_id': [4698]},
        },
        {
            'id': 'phoenix-account-created',
            'title': 'User Account Created',
            'description': 'Creation de compte utilisateur (Event 4720)',
            'level': 'medium',
            'tactic': 'persistence', 'technique': 'T1136.001',
            'logsource': {'product': 'windows', 'service': 'security'},
            'detection': {'event_id': [4720]},
        },
        {
            'id': 'phoenix-account-added-admin',
            'title': 'User Added to Admin Group',
            'description': 'Ajout d\'un compte au groupe Administrateurs (Event 4732)',
            'level': 'high',
            'tactic': 'privilege_escalation', 'technique': 'T1078',
            'logsource': {'product': 'windows', 'service': 'security'},
            'detection': {'event_id': [4732]},
        },
        {
            'id': 'phoenix-registry-runkey',
            'title': 'Registry Run Key Modified',
            'description': 'Modification d\'une cle Run (autorun)',
            'level': 'medium',
            'tactic': 'persistence', 'technique': 'T1547.001',
            'logsource': {'product': 'windows', 'service': 'sysmon'},
            'detection': {'event_id': [13], 'target_object_contains': '\\CurrentVersion\\Run'},
        },
        {
            'id': 'phoenix-wmi-subscription',
            'title': 'WMI Event Subscription',
            'description': 'Creation d\'abonnement WMI persistant (Event 5861)',
            'level': 'high',
            'tactic': 'persistence', 'technique': 'T1546.003',
            'logsource': {'product': 'windows', 'service': 'wmi'},
            'detection': {'event_id': [5861]},
        },

        # === Privilege Escalation (TA0004) ===
        {
            'id': 'phoenix-privilege-escalation',
            'title': 'Special Privileges Assigned',
            'description': 'Attribution de privileges speciaux (Event 4672)',
            'level': 'low',
            'tactic': 'privilege_escalation', 'technique': 'T1078',
            'logsource': {'product': 'windows', 'service': 'security'},
            'detection': {'event_id': [4672]},
        },

        # === Execution (TA0002) ===
        {
            'id': 'phoenix-powershell-encoded',
            'title': 'Encoded PowerShell',
            'description': 'PowerShell avec parametre -EncodedCommand (obfuscation)',
            'level': 'high',
            'tactic': 'execution', 'technique': 'T1059.001',
            'logsource': {'product': 'windows', 'service': 'sysmon'},
            'detection': {'event_id': [1], 'command_line_contains': '-encodedcommand'},
        },
        {
            'id': 'phoenix-wmic-exec',
            'title': 'WMIC Process Execution',
            'description': 'Execution de processus via wmic.exe',
            'level': 'medium',
            'tactic': 'execution', 'technique': 'T1047',
            'logsource': {'product': 'windows', 'service': 'sysmon'},
            'detection': {'event_id': [1], 'image_contains': 'wmic.exe',
                          'command_line_contains': 'process call create'},
        },
        {
            'id': 'phoenix-mshta-exec',
            'title': 'Mshta Execution',
            'description': 'Execution de mshta.exe (LOLBin frequent)',
            'level': 'high',
            'tactic': 'defense_evasion', 'technique': 'T1218.005',
            'logsource': {'product': 'windows', 'service': 'sysmon'},
            'detection': {'event_id': [1], 'image_contains': 'mshta.exe'},
        },
        {
            'id': 'phoenix-rundll32-exec',
            'title': 'Suspicious Rundll32 Execution',
            'description': 'Execution suspecte de rundll32 (LOLBin)',
            'level': 'medium',
            'tactic': 'defense_evasion', 'technique': 'T1218.011',
            'logsource': {'product': 'windows', 'service': 'sysmon'},
            'detection': {'event_id': [1], 'image_contains': 'rundll32.exe'},
        },

        # === Lateral Movement (TA0008) ===
        {
            'id': 'phoenix-psexec',
            'title': 'PsExec Service Installation',
            'description': 'Installation du service PSEXESVC (mouvement lateral)',
            'level': 'high',
            'tactic': 'lateral_movement', 'technique': 'T1021.002',
            'logsource': {'product': 'windows', 'service': 'system'},
            'detection': {'event_id': [7045], 'service_name_contains': 'PSEXESVC'},
        },
        {
            'id': 'phoenix-rdp-success',
            'title': 'RDP Logon Success',
            'description': 'Connexion RDP reussie (Event 4624 type 10)',
            'level': 'low',
            'tactic': 'lateral_movement', 'technique': 'T1021.001',
            'logsource': {'product': 'windows', 'service': 'security'},
            'detection': {'event_id': [4624], 'logon_type': 10},
        },

        # === Exfiltration / C2 (TA0010/TA0011) ===
        {
            'id': 'phoenix-bitsadmin-download',
            'title': 'BITSAdmin Download',
            'description': 'Download via bitsadmin (often used by malware)',
            'level': 'high',
            'tactic': 'command_and_control', 'technique': 'T1105',
            'logsource': {'product': 'windows', 'service': 'sysmon'},
            'detection': {'event_id': [1], 'image_contains': 'bitsadmin.exe',
                          'command_line_contains': '/transfer'},
        },
        {
            'id': 'phoenix-certutil-download',
            'title': 'Certutil Used for Download',
            'description': 'certutil.exe utilise pour telecharger (LOLBin C2)',
            'level': 'high',
            'tactic': 'command_and_control', 'technique': 'T1105',
            'logsource': {'product': 'windows', 'service': 'sysmon'},
            'detection': {'event_id': [1], 'image_contains': 'certutil.exe',
                          'command_line_contains': 'urlcache'},
        },

        # === Impact (TA0040) - Ransomware ===
        {
            'id': 'phoenix-vss-delete',
            'title': 'Volume Shadow Copy Deletion',
            'description': 'Suppression des shadow copies (typique ransomware)',
            'level': 'critical',
            'tactic': 'impact', 'technique': 'T1490',
            'logsource': {'product': 'windows', 'service': 'sysmon'},
            'detection': {'event_id': [1], 'command_line_contains': 'vssadmin delete shadows'},
        },
        {
            'id': 'phoenix-wbadmin-delete',
            'title': 'Backup Catalog Deletion',
            'description': 'Suppression catalogue de sauvegarde via wbadmin',
            'level': 'critical',
            'tactic': 'impact', 'technique': 'T1490',
            'logsource': {'product': 'windows', 'service': 'sysmon'},
            'detection': {'event_id': [1], 'image_contains': 'wbadmin.exe',
                          'command_line_contains': 'delete catalog'},
        },
        {
            'id': 'phoenix-bcdedit-recovery',
            'title': 'Boot Configuration Tampering',
            'description': 'Desactivation de la recuperation systeme (bcdedit)',
            'level': 'critical',
            'tactic': 'impact', 'technique': 'T1490',
            'logsource': {'product': 'windows', 'service': 'sysmon'},
            'detection': {'event_id': [1], 'image_contains': 'bcdedit.exe',
                          'command_line_contains': 'recoveryenabled no'},
        },
    ]

    def test_connection(self):
        """Verifier les regles Sigma disponibles"""
        rules_path = self.get_config('rules_path', '')
        custom_count = 0

        if rules_path and os.path.isdir(rules_path):
            for fname in os.listdir(rules_path):
                if fname.endswith(('.yml', '.yaml')):
                    custom_count += 1

        return {
            'success': True,
            'message': f'{len(self.BUILTIN_RULES)} regles integrees, {custom_count} regles personnalisees',
            'builtin_rules': len(self.BUILTIN_RULES),
            'custom_rules': custom_count,
        }

    # Champs de criteres "*_contains" (substring case-insensitive)
    _CONTAINS_CRITERIA = (
        ('object_name_contains', 'object_name'),
        ('target_image_contains', 'target_image'),
        ('image_contains', 'image'),
        ('command_line_contains', 'command_line'),
        ('target_object_contains', 'target_object'),
        ('service_name_contains', 'service_name'),
    )

    # Champs de criteres "field == valeur exacte" (case-insensitive si str)
    _EQUALITY_CRITERIA = (
        ('logon_type', 'logon_type'),
        ('ticket_encryption', 'ticket_encryption'),
    )

    def _match_event(self, rule_detection, event):
        """Verifie tous les criteres optionnels d'une regle contre un evenement."""
        # event_id deja verifie en amont
        for crit_key, event_key in self._CONTAINS_CRITERIA:
            expected = rule_detection.get(crit_key)
            if expected is None:
                continue
            actual = event.get(event_key, '')
            if not isinstance(actual, str):
                return False
            if expected.lower() not in actual.lower():
                return False

        for crit_key, event_key in self._EQUALITY_CRITERIA:
            expected = rule_detection.get(crit_key)
            if expected is None:
                continue
            actual = event.get(event_key)
            if isinstance(expected, str) and isinstance(actual, str):
                if expected.lower() != actual.lower():
                    return False
            elif expected != actual:
                return False
        return True

    def search(self, query, **kwargs):
        """Appliquer les regles Sigma sur des evenements"""
        events = kwargs.get('events', [])
        if not events:
            return {'success': False, 'message': 'Liste d\'evenements requise'}

        # Filtre optionnel par tactique
        tactic_filter = kwargs.get('tactic')

        alerts = []
        threshold_counts = {}  # rule_id -> count pour seuils
        for rule in self.BUILTIN_RULES:
            if tactic_filter and rule.get('tactic') != tactic_filter:
                continue
            detection = rule.get('detection', {})
            rule_event_ids = detection.get('event_id', [])

            for event in events:
                event_id = event.get('event_id')
                if event_id is None or event_id not in rule_event_ids:
                    continue
                if not self._match_event(detection, event):
                    continue

                # Gestion des seuils (ex: brute force = 5 echecs)
                threshold = detection.get('threshold')
                if threshold:
                    threshold_counts[rule['id']] = threshold_counts.get(rule['id'], 0) + 1
                    if threshold_counts[rule['id']] < threshold:
                        continue

                alerts.append({
                    'rule_id': rule['id'],
                    'rule_title': rule['title'],
                    'description': rule['description'],
                    'level': rule['level'],
                    'tactic': rule.get('tactic'),
                    'technique': rule.get('technique'),
                    'event': event,
                })

        return {
            'success': True,
            'alerts': alerts,
            'total_alerts': len(alerts),
            'rules_evaluated': len(self.BUILTIN_RULES) if not tactic_filter else
                               sum(1 for r in self.BUILTIN_RULES if r.get('tactic') == tactic_filter),
            'events_scanned': len(events),
            'message': f'{len(alerts)} alerte(s) Sigma declenchee(s)',
        }

    def pull_iocs(self, query=None, limit=100):
        """Retourner la liste des regles Sigma disponibles"""
        rules = []
        for rule in self.BUILTIN_RULES:
            rules.append({
                'type': 'sigma_rule',
                'value': rule['id'],
                'source': 'phoenix-builtin',
                'severity': rule['level'],
                'metadata': rule,
            })
        return {
            'success': True,
            'iocs': rules,
            'total': len(rules),
            'message': f'{len(rules)} regles Sigma disponibles',
        }
