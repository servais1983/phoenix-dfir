#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phoenix DFIR Service
Service d'intégration pour les fonctionnalités Phoenix DFIR
"""

import os
import sys
import json
import datetime
import requests
import pandas as pd
import ast
from pathlib import Path

# Configuration des modèles IA
MODEL_LOCAL = 'phi3:mini'
MODEL_REMOTE = 'gemini-1.5-flash'
API_KEY_GOOGLE = "VOTRE_CLE_API_GOOGLE_ICI"
API_KEY_VT = "VOTRE_CLE_API_VIRUSTOTAL_ICI"

# Import optionnel pour EVTX
try:
    import Evtx.Evtx as evtx
    import xml.etree.ElementTree as ET
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False

# Import optionnel pour Ollama
try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

# Import optionnel pour Google AI
try:
    import google.generativeai as genai
    GOOGLE_AI_AVAILABLE = True
except ImportError:
    GOOGLE_AI_AVAILABLE = False

class PhoenixService:
    """Service principal pour les fonctionnalités Phoenix DFIR"""
    
    def __init__(self):
        self.session_data = {}
        self.setup_ai_models()
    
    def setup_ai_models(self):
        """Configuration des modèles IA"""
        if GOOGLE_AI_AVAILABLE and API_KEY_GOOGLE != "VOTRE_CLE_API_GOOGLE_ICI":
            try:
                genai.configure(api_key=API_KEY_GOOGLE)
                self.google_model = genai.GenerativeModel(MODEL_REMOTE)
            except Exception as e:
                print(f"Erreur configuration Google AI: {e}")
                self.google_model = None
        else:
            self.google_model = None
    
    def query_local(self, prompt):
        """Requête vers le modèle local (Ollama)"""
        if not OLLAMA_AVAILABLE:
            return "Erreur: Ollama non disponible"
        
        try:
            response = ollama.chat(
                model=MODEL_LOCAL,
                messages=[{'role': 'user', 'content': prompt}]
            )
            return response['message']['content']
        except Exception as e:
            return f"Erreur Ollama: {e}"
    
    def query_remote(self, prompt):
        """Requête vers le modèle distant (Google AI)"""
        if not self.google_model:
            return "Erreur: Google AI non configuré"
        
        try:
            response = self.google_model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Erreur Google AI: {e}"
    
    def enrichir_ioc_vt(self, ioc_type, ioc_value):
        """Enrichissement IoC via VirusTotal"""
        if API_KEY_VT == "VOTRE_CLE_API_VIRUSTOTAL_ICI":
            return "VirusTotal non configuré"
        
        normalized_ioc_type = ioc_type.rstrip('s')
        
        if normalized_ioc_type == 'ip':
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
        elif normalized_ioc_type == 'domaine':
            url = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
        elif normalized_ioc_type == 'hash':
            url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
        else:
            return "Type d'IoC non supporté"
        
        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY_VT
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious_score = stats.get("malicious", 0)
            owner = attributes.get("as_owner", "N/A")
            country = attributes.get("country", "N/A")
            
            return f"VirusTotal ({country}) - Propriétaire: {owner} | Score Malveillant: {malicious_score}"
            
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                return "Non trouvé sur VirusTotal"
            return f"Erreur HTTP VT: {e}"
        except Exception as e:
            return f"Erreur enrichissement: {e}"
    
    def handle_csv(self, filename, user_query, investigation_data):
        """Gestionnaire pour fichiers CSV"""
        try:
            df = pd.read_csv(filename)
            column_names = ", ".join(df.columns)
            
            # Contexte d'enquête
            contexte_enquete = ""
            ip_values = []
            
            if investigation_data and investigation_data.get('iocs', {}).get('ips'):
                ip_values = [ip_obj.get('valeur') for ip_obj in investigation_data['iocs']['ips']]
                if ip_values:
                    contexte_enquete = f"Contexte de l'enquête : les IPs déjà identifiées comme pertinentes sont {ip_values}. La variable Python contenant cette liste est 'ips_connues'."
            
            # Génération du code d'analyse
            code_generation_prompt = f"""Expert DFIR avec Pandas. Un DataFrame 'df' a les colonnes [{column_names}]. {contexte_enquete} La demande de l'utilisateur est : "{user_query}". Ta mission est de répondre avec UNE SEULE LIGNE de code Python pour filtrer 'df'. Le résultat DOIT être dans une variable nommée 'resultat'. NE FOURNIS AUCUNE EXPLICATION, AUCUN COMMENTAIRE, AUCUN TEXTE. Juste la ligne de code."""
            
            generated_response = self.query_remote(code_generation_prompt)
            
            # Extraction du code
            code_line = ""
            cleaned_response = generated_response.replace("```python", "").replace("```", "")
            
            for line in cleaned_response.splitlines():
                if "resultat =" in line:
                    code_line = line.strip()
                    break
            
            if not code_line:
                return f"Erreur: L'IA n'a pas généré de code exécutable valide. Réponse reçue:\n{generated_response}"
            
            # Validation syntaxique
            try:
                ast.parse(code_line)
            except SyntaxError as e:
                return f"Erreur: Code généré invalide (erreur de syntaxe) :\n{code_line}\nDétail : {e}"
            
            # Exécution du code
            exec_scope = {'df': df, 'pd': pd}
            if 'ips_connues' in code_line:
                exec_scope['ips_connues'] = ip_values
            
            try:
                exec(code_line, exec_scope)
                return exec_scope.get('resultat', "Le code n'a pas retourné de 'resultat'.")
            except Exception as e:
                return f"Erreur: Erreur lors de l'exécution du code généré par l'IA : {e}"
                
        except Exception as e:
            return f"Erreur lors de l'analyse CSV: {e}"
    
    def handle_json(self, filename, user_query, investigation_data):
        """Gestionnaire pour fichiers JSON"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            structure = list(data.keys())
            analysis_prompt = f"Analyste DFIR. Un JSON a les clés principales: {structure}. Demande: \"{user_query}\". Analyse cet extrait: {str(data)[:2000]}"
            
            return self.query_local(analysis_prompt)
            
        except Exception as e:
            return f"Erreur lors de l'analyse JSON: {e}"
    
    def handle_generic_text(self, filename, user_query, investigation_data):
        """Gestionnaire pour fichiers texte génériques"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
            
            analysis_prompt = f"Analyste DFIR. Fichier '{filename}' contient: \"{user_query}\". Analyse ce contenu:\n---\n{content}\n---"
            
            return self.query_local(analysis_prompt)
            
        except Exception as e:
            return f"Erreur lors de l'analyse du fichier texte: {e}"
    
    def handle_evtx(self, filename, user_query, investigation_data, event_id_filter=None):
        """Gestionnaire pour fichiers EVTX"""
        if not EVTX_AVAILABLE:
            return "Erreur: La librairie 'python-evtx' est nécessaire pour analyser ce fichier. Veuillez l'installer avec 'pip install python-evtx'."
        
        try:
            parsed_records = []
            record_limit = 50
            
            with evtx.Evtx(filename) as log:
                for record in log.records():
                    if len(parsed_records) >= record_limit:
                        break
                    
                    try:
                        xml_data = record.xml()
                        xml_data_clean = xml_data.replace(
                            ' xmlns="http://schemas.microsoft.com/win/2004/08/events/event"',
                            '', 1
                        )
                        
                        root = ET.fromstring(xml_data_clean)
                        system_node = root.find('System')
                        event_id_node = system_node.find('EventID')
                        
                        if event_id_node is None:
                            continue
                        
                        event_id = int(event_id_node.text)
                        
                        if event_id_filter is None or event_id == event_id_filter:
                            event_data_node = root.find('EventData')
                            event_data = {}
                            
                            if event_data_node is not None:
                                for i, child in enumerate(event_data_node):
                                    key = child.attrib.get('Name', f'Data{i}')
                                    event_data[key] = child.text
                            
                            parsed_records.append({
                                "timestamp_utc": record.timestamp().isoformat(),
                                "event_id": event_id,
                                "data": event_data
                            })
                            
                    except Exception:
                        continue
            
            if not parsed_records:
                return "Aucun enregistrement trouvé avec ces critères."
            
            analysis_prompt = f"Analyste DFIR expert des logs Windows. La question est : \"{user_query}\". Analyse ces événements, cherche des anomalies et réponds de manière structurée. Événements :\n{json.dumps(parsed_records, indent=2)}"
            
            return self.query_local(analysis_prompt)
            
        except Exception as e:
            return f"Erreur lors de l'analyse EVTX: {e}"
    
    def analyze_file(self, filename, user_query, investigation_data, event_id_filter=None):
        """Analyser un fichier selon son type"""
        try:
            _, extension = os.path.splitext(filename.lower())
            
            if extension == '.evtx':
                return self.handle_evtx(filename, user_query, investigation_data, event_id_filter)
            elif extension == '.csv':
                return self.handle_csv(filename, user_query, investigation_data)
            elif extension == '.json':
                return self.handle_json(filename, user_query, investigation_data)
            elif extension in ['.log', '.txt', '.xml', '.ps1', '.bat', '.sh']:
                return self.handle_generic_text(filename, user_query, investigation_data)
            else:
                return self.handle_generic_text(filename, user_query, investigation_data)
                
        except FileNotFoundError:
            return f"Erreur: Fichier '{filename}' introuvable."
        except Exception as e:
            return f"Erreur: Erreur inattendue durant l'analyse : {e}"
    
    def extract_iocs_and_timeline(self, analysis_text, filename):
        """Extraire les IoCs et la timeline d'un rapport d'analyse"""
        extraction_prompt = f"""Robot d'extraction DFIR. Lis ce rapport. Extrais les infos. Réponds UNIQUEMENT en JSON. Le format doit être :{{"ips": ["ip1", ...], "hashes": [], "domaines": [], "timeline": [{{"timestamp": "YYYY-MM-DDTHH:MM:SS", "event": "Description courte et factuelle."}},...], "resume": "Résumé court."}}. Si vide, liste vide. Cherche activement des timestamps. Rapport :\n---\n{analysis_text}\n---"""
        
        json_response_str = self.query_remote(extraction_prompt)
        cleaned_json_str = json_response_str.replace("```json", "").replace("```", "").strip()
        
        try:
            extracted_data = json.loads(cleaned_json_str)
            return extracted_data
        except Exception as e:
            print(f"Erreur lors de l'extraction des IoCs: {e}")
            return {
                "ips": [],
                "hashes": [],
                "domaines": [],
                "timeline": [],
                "resume": "Erreur lors de l'extraction automatique"
            }
    
    def update_investigation_with_analysis(self, investigation_data, analysis_text, filename):
        """Mettre à jour les données d'enquête avec les résultats d'analyse"""
        try:
            # Extraire les IoCs et timeline
            extracted_data = self.extract_iocs_and_timeline(analysis_text, filename)
            
            # Ajouter l'artefact analysé
            if "artefacts_analyses" not in investigation_data:
                investigation_data["artefacts_analyses"] = []
            
            investigation_data["artefacts_analyses"].append({
                "fichier": filename,
                "type_analyse": "IA",
                "resume": extracted_data.get("resume", "N/A"),
                "date_analyse": datetime.datetime.now().isoformat()
            })
            
            # Ajouter les événements de timeline
            if "timeline_events" not in investigation_data:
                investigation_data["timeline_events"] = []
            
            for event in extracted_data.get("timeline", []):
                investigation_data["timeline_events"].append(event)
            
            # Enrichir les nouveaux IoCs
            for ioc_type, ioc_list in extracted_data.items():
                if ioc_type in investigation_data.get("iocs", {}) and isinstance(ioc_list, list):
                    for ioc_value in ioc_list:
                        # Vérifier si l'IoC est nouveau
                        is_new = not any(
                            d.get('valeur') == ioc_value 
                            for d in investigation_data["iocs"][ioc_type]
                        )
                        
                        if is_new:
                            enrichment_data = self.enrichir_ioc_vt(ioc_type, ioc_value)
                            investigation_data["iocs"][ioc_type].append({
                                "valeur": ioc_value,
                                "source": filename,
                                "enrichissement_vt": enrichment_data,
                                "date_decouverte": datetime.datetime.now().isoformat()
                            })
            
            # Mettre à jour la dernière activité
            investigation_data["derniere_activite"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            return investigation_data
            
        except Exception as e:
            print(f"Erreur lors de la mise à jour de l'enquête: {e}")
            return investigation_data
    
    def generate_executive_summary(self, investigation_data):
        """Générer un résumé exécutif"""
        contexte_simplifie = {
            "nom_du_cas": investigation_data.get("nom_du_cas"),
            "artefacts_analyses": [
                item['resume'] for item in investigation_data.get("artefacts_analyses", [])
            ],
            "iocs": investigation_data.get("iocs")
        }
        
        prompt = f"Expert cybersécurité. Voici les données d'une enquête : {json.dumps(contexte_simplifie, indent=2)}. Rédige un résumé exécutif (3-5 phrases) qui synthétise la situation, les IoCs clés et la conclusion. Sois professionnel et factuel."
        
        return self.query_remote(prompt)
    
    def create_report_content(self, investigation_data, executive_summary):
        """Créer le contenu du rapport"""
        report_content = f"# Rapport d'Enquête : {investigation_data.get('nom_du_cas')}\n\n"
        report_content += f"**Date de génération :** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report_content += f"**Date de création du cas :** {investigation_data.get('date_creation')}\n\n"
        
        report_content += "## Résumé Exécutif\n\n"
        report_content += f"{executive_summary}\n\n"
        
        report_content += "## Artefacts Analysés\n\n"
        for artefact in investigation_data.get("artefacts_analyses", []):
            report_content += f"- **Fichier :** `{artefact.get('fichier')}`\n"
            report_content += f"  - **Résumé IA :** {artefact.get('resume')}\n"
            report_content += f"  - **Date d'analyse :** {artefact.get('date_analyse', 'N/A')}\n\n"
        
        report_content += "## Indicateurs de Compromission (IoCs)\n\n"
        for ioc_type, ioc_list in investigation_data.get("iocs", {}).items():
            if ioc_list:
                report_content += f"### {ioc_type.upper()}\n\n"
                for ioc in ioc_list:
                    report_content += f"- **Valeur :** `{ioc.get('valeur')}`\n"
                    report_content += f"  - **Source :** `{ioc.get('source')}`\n"
                    report_content += f"  - **Enrichissement VT :** {ioc.get('enrichissement_vt')}\n"
                    report_content += f"  - **Date de découverte :** {ioc.get('date_decouverte', 'N/A')}\n\n"
        
        report_content += "## Timeline des Événements\n\n"
        if investigation_data.get("timeline_events"):
            sorted_events = sorted(
                investigation_data.get("timeline_events", []),
                key=lambda x: x.get('timestamp', '')
            )
            for event in sorted_events:
                report_content += f"- **`{event.get('timestamp', 'N/A')}`** : {event.get('event')}\n"
        else:
            report_content += "_Aucun événement avec timestamp n'a été extrait des analyses._\n"
        
        return report_content

# Instance globale du service
phoenix_service = PhoenixService()
