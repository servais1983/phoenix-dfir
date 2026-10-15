"""
Phoenix DFIR - YARA Rule Engine Connector
Matching de regles YARA sur les artefacts
"""

import os
import tempfile
from integrations.base import BaseConnector
from integrations import registry


@registry.register
class YARAConnector(BaseConnector):
    CONNECTOR_ID = 'yara'
    CONNECTOR_NAME = 'YARA'
    CONNECTOR_DESCRIPTION = 'Moteur de regles YARA - Detection de malware par signatures et patterns'
    CONNECTOR_ICON = 'file-search'
    CONNECTOR_URL = 'https://virustotal.github.io/yara/'
    CONNECTOR_CATEGORY = 'rule_engine'

    CONFIG_SCHEMA = [
        {'key': 'rules_path', 'label': 'Dossier des regles YARA', 'type': 'text', 'required': False, 'placeholder': '/path/to/yara/rules'},
        {'key': 'custom_rules', 'label': 'Regles YARA personnalisees', 'type': 'textarea', 'required': False, 'placeholder': 'rule example { strings: $a = "malware" condition: $a }'},
    ]

    def test_connection(self):
        """Verifier que YARA est installe"""
        try:
            import yara
            return {
                'success': True,
                'message': f'YARA disponible (v{yara.YARA_VERSION})',
                'version': yara.YARA_VERSION,
            }
        except ImportError:
            return {
                'success': False,
                'message': 'Module yara-python non installe (pip install yara-python)',
            }

    def search(self, query, **kwargs):
        """Scanner un fichier avec des regles YARA"""
        filepath = kwargs.get('filepath')
        if not filepath or not os.path.exists(filepath):
            return {'success': False, 'message': 'Fichier requis pour le scan YARA'}

        try:
            import yara
        except ImportError:
            return {'success': False, 'message': 'yara-python non installe'}

        rules_sources = {}
        matches_result = []

        # Charger les regles depuis le dossier configure
        rules_path = self.get_config('rules_path', '')
        if rules_path and os.path.isdir(rules_path):
            for fname in os.listdir(rules_path):
                if fname.endswith(('.yar', '.yara')):
                    fpath = os.path.join(rules_path, fname)
                    rules_sources[fname] = fpath

        # Charger les regles personnalisees
        custom_rules = self.get_config('custom_rules', '')
        if custom_rules:
            tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False)
            tmp.write(custom_rules)
            tmp.close()
            rules_sources['custom_rules'] = tmp.name

        if not rules_sources:
            return {'success': False, 'message': 'Aucune regle YARA configuree'}

        try:
            if len(rules_sources) == 1:
                key, path = next(iter(rules_sources.items()))
                if key == 'custom_rules':
                    rules = yara.compile(filepath=path)
                else:
                    rules = yara.compile(filepath=path)
            else:
                rules = yara.compile(filepaths=rules_sources)

            matches = rules.match(filepath)

            for match in matches:
                matches_result.append({
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': [{'offset': s[0], 'identifier': s[1], 'data': s[2].hex()[:100]} for s in match.strings[:10]],
                })

        except yara.SyntaxError as e:
            return {'success': False, 'message': f'Erreur syntaxe YARA: {e}'}
        except Exception as e:
            return {'success': False, 'message': f'Erreur YARA: {e}'}
        finally:
            # Nettoyer le fichier temporaire
            if custom_rules:
                try:
                    os.unlink(tmp.name)
                except Exception:
                    pass

        return {
            'success': True,
            'matches': matches_result,
            'total_matches': len(matches_result),
            'rules_loaded': len(rules_sources),
            'message': f'{len(matches_result)} regle(s) YARA matchee(s)',
        }
