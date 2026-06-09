# ==============================================================================
# PHOENIX - VERSION FINALE STABLE ET COMPLETE
# ==============================================================================

# --- Imports et Configuration ---
import typer
import ollama
import google.generativeai as genai
import pandas as pd
import json
import os
import datetime
import pprint
import requests
import ast

# Un import optionnel, on gère le cas où il n'est pas là
try:
    import Evtx.Evtx as evtx
    import xml.etree.ElementTree as ET
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False

# --- CONFIGURATION ---
MODEL_LOCAL = 'phi3:mini' 
MODEL_REMOTE = 'gemini-1.5-flash'
API_KEY_GOOGLE = "VOTRE_CLE_API_GOOGLE_ICI"
API_KEY_VT = "VOTRE_CLE_API_VIRUSTOTAL_ICI"
SESSION_FICHIER = "session_enquete.json"

# --- FONCTIONS DE GESTION DE SESSION ---
def sauvegarder_session(donnees_enquete):
    try:
        with open(SESSION_FICHIER, 'w', encoding='utf-8') as f:
            json.dump(donnees_enquete, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        typer.secho(f"Erreur critique lors de la sauvegarde de la session : {e}", fg=typer.colors.RED)
        return False

def charger_session():
    try:
        if os.path.exists(SESSION_FICHIER):
            with open(SESSION_FICHIER, 'r', encoding='utf-8') as f:
                return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    return {}

# --- INITIALISATION DE L'APPLICATION TYPER ---
app = typer.Typer(
    help="Phoenix : Assistant d'Investigation DFIR Intégré (Version Finale).",
    add_completion=False, rich_markup_mode="markdown"
)

# --- FONCTIONS "COEUR" ---
def query_local(prompt):
    typer.echo(f"\n--- [PHOENIX-CORE] Utilisation du modèle local: {MODEL_LOCAL}...")
    try:
        response = ollama.chat(model=MODEL_LOCAL, messages=[{'role': 'user', 'content': prompt}])
        return response['message']['content']
    except Exception as e: return f"Erreur: Connexion au Coeur Phoenix (Ollama) impossible. Détail: {e}"

def query_remote(prompt):
    typer.echo(f"\n--- [PHOENIX-AUGMENTED] Utilisation du modèle distant: {MODEL_REMOTE}...")
    try:
        genai.configure(api_key=API_KEY_GOOGLE)
        model = genai.GenerativeModel(MODEL_REMOTE)
        response = model.generate_content(prompt)
        return response.text
    except Exception as e: return f"Erreur: Connexion au Cerveau Augmenté impossible. Détail: {e}"

def enrichir_ioc_vt(ioc_type, ioc_value):
    typer.echo(f"\n--- [PHOENIX-THREATINTEL] Enrichissement de '{ioc_value}' via VirusTotal...")
    normalized_ioc_type = ioc_type.rstrip('s')
    if normalized_ioc_type == 'ip': url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
    elif normalized_ioc_type == 'domaine': url = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
    elif normalized_ioc_type == 'hash': url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
    else: return "Type d'IoC non supporté."
    headers = {"accept": "application/json", "x-apikey": API_KEY_VT}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious_score = stats.get("malicious", 0)
        owner = attributes.get("as_owner", "N/A")
        country = attributes.get("country", "N/A")
        return (f"Rapport VirusTotal ({country}) - Propriétaire: {owner} | Score Malveillant: {malicious_score}")
    except requests.HTTPError as e:
        if e.response.status_code == 404: return f"Info: Non trouvé sur VirusTotal."
        return f"Erreur HTTP VT : {e}"
    except Exception as e: return f"Erreur durant l'enrichissement : {e}"

# --- GESTIONNAIRES D'ANALYSE DE FICHIERS ---
def handle_csv(filename, user_query, dossier_enquete):
    typer.echo(f"--- [CSV Handler] Analyse de {filename} ---")
    df = pd.read_csv(filename)
    column_names = ", ".join(df.columns)
    contexte_enquete = ""
    ip_values = []
    if dossier_enquete and dossier_enquete.get('iocs', {}).get('ips'):
        ip_values = [ip_obj.get('valeur') for ip_obj in dossier_enquete['iocs']['ips']]
        if ip_values:
            contexte_enquete = f"Contexte de l'enquête : les IPs déjà identifiées comme pertinentes sont {ip_values}. La variable Python contenant cette liste est 'ips_connues'."
    code_generation_prompt = f"""Expert DFIR avec Pandas. Un DataFrame 'df' a les colonnes [{column_names}]. {contexte_enquete} La demande de l'utilisateur est : "{user_query}". Ta mission est de répondre avec UNE SEULE LIGNE de code Python pour filtrer 'df'. Le résultat DOIT être dans une variable nommée 'resultat'. NE FOURNIS AUCUNE EXPLICATION, AUCUN COMMENTAIRE, AUCUN TEXTE. Juste la ligne de code."""
    generated_response = query_remote(code_generation_prompt)
    code_line = ""
    cleaned_response = generated_response.replace("```python", "").replace("```", "")
    for line in cleaned_response.splitlines():
        if "resultat =" in line:
            code_line = line.strip()
            break
    if not code_line: return f"Erreur: L'IA n'a pas généré de code exécutable valide. Réponse reçue:\n{generated_response}"
    try:
        ast.parse(code_line)
    except SyntaxError as e: return f"Erreur: Code généré invalide (erreur de syntaxe) :\n{code_line}\nDétail : {e}"
    typer.echo(f"--- [PHOENIX-AI-DEV] Code isolé et validé : {code_line} ---")
    exec_scope = {'df': df, 'pd': pd}
    if 'ips_connues' in code_line: exec_scope['ips_connues'] = ip_values
    try:
        exec(code_line, exec_scope)
        return exec_scope.get('resultat', "Le code n'a pas retourné de 'resultat'.")
    except Exception as e: return f"Erreur: Erreur lors de l'exécution du code généré par l'IA : {e}"

def handle_json(filename, user_query, dossier_enquete):
    typer.echo(f"--- [JSON Handler] Analyse de {filename} ---")
    with open(filename, 'r', encoding='utf-8') as f: data = json.load(f)
    structure = list(data.keys())
    analysis_prompt = f"Analyste DFIR. Un JSON a les clés principales: {structure}. Demande: \"{user_query}\". Analyse cet extrait: {str(data)[:2000]}"
    return query_local(analysis_prompt)

def handle_generic_text(filename, user_query, dossier_enquete):
    typer.echo(f"--- [Text Handler] Analyse de {filename} ---")
    with open(filename, 'r', encoding='utf-8') as f: content = f.read()
    analysis_prompt = f"Analyste DFIR. Fichier '{filename}' contient: \"{user_query}\". Analyse ce contenu:\n---\n{content}\n---"
    return query_local(analysis_prompt)

def handle_evtx(filename, user_query, dossier_enquete, event_id_filter=None):
    if not EVTX_AVAILABLE:
        return "Erreur: La librairie 'python-evtx' est nécessaire pour analyser ce fichier. Veuillez l'installer avec 'pip install python-evtx'."
    typer.echo(f"--- [EVTX Handler] Analyse de {filename} ---")
    if event_id_filter:
        typer.echo(f"--- Filtre appliqué : recherche de l'Event ID = {event_id_filter} ---")
    parsed_records, record_limit = [], 50
    try:
        with evtx.Evtx(filename) as log:
            for record in log.records():
                if len(parsed_records) >= record_limit:
                    typer.secho(f"Limite de {record_limit} enregistrements atteinte.", fg=typer.colors.YELLOW); break
                try:
                    xml_data = record.xml()
                    xml_data_clean = xml_data.replace(' xmlns="http://schemas.microsoft.com/win/2004/08/events/event"', '', 1)
                    root = ET.fromstring(xml_data_clean)
                    system_node = root.find('System')
                    event_id_node = system_node.find('EventID')
                    if event_id_node is None: continue
                    event_id = int(event_id_node.text)
                    if event_id_filter is None or event_id == event_id_filter:
                        event_data_node = root.find('EventData')
                        event_data = {child.attrib.get('Name', f'Data{i}'): child.text for i, child in enumerate(event_data_node)} if event_data_node is not None else {}
                        parsed_records.append({"timestamp_utc": record.timestamp().isoformat(), "event_id": event_id, "data": event_data})
                except Exception: continue
    except Exception as e: return f"Erreur: Erreur majeure lors du parsing EVTX : {e}"
    if not parsed_records: return "Aucun enregistrement trouvé avec ces critères."
    analysis_prompt = f"Analyste DFIR expert des logs Windows. La question est : \"{user_query}\". Analyse ces événements, cherche des anomalies et réponds de manière structurée. Événements :\n{json.dumps(parsed_records, indent=2)}"
    return query_local(analysis_prompt)

def analyse_fichier(filename, user_query, dossier_enquete, event_id_filter=None):
    try:
        _, extension = os.path.splitext(filename.lower())
        if extension == '.evtx': return handle_evtx(filename, user_query, dossier_enquete, event_id_filter)
        elif extension == '.csv': return handle_csv(filename, user_query, dossier_enquete)
        elif extension == '.json': return handle_json(filename, user_query, dossier_enquete)
        elif extension in ['.log', '.txt', '.xml', '.ps1', '.bat', '.sh']: return handle_generic_text(filename, user_query, dossier_enquete)
        else:
            typer.echo(f"Format '{extension}' non spécialisé. Analyse texte..."); return handle_generic_text(filename, user_query, dossier_enquete)
    except FileNotFoundError: return f"Erreur: Fichier '{filename}' introuvable."
    except Exception as e: return f"Erreur: Erreur inattendue durant l'analyse : {e}"

def extraire_et_sauvegarder_conclusions(dossier_enquete, analyse_text, filename):
    typer.echo("\n--- [PHOENIX-CORRELATION] Phase 1: Extraction des IoCs et Timestamps...")
    extraction_prompt = f"""Robot d'extraction DFIR. Lis ce rapport. Extrais les infos. Réponds UNIQUEMENT en JSON. Le format doit être :{{"ips": ["ip1", ...], "hashes": [], "domaines": [], "timeline": [{{"timestamp": "YYYY-MM-DDTHH:MM:SS", "event": "Description courte et factuelle."}},...], "resume": "Résumé court."}}. Si vide, liste vide. Cherche activement des timestamps. Rapport :\n---\n{analyse_text}\n---"""
    json_response_str = query_remote(extraction_prompt)
    cleaned_json_str = json_response_str.replace("```json", "").replace("```", "").strip()
    try:
        extracted_data = json.loads(cleaned_json_str)
        if "artefacts_analyses" not in dossier_enquete: dossier_enquete["artefacts_analyses"] = []
        dossier_enquete["artefacts_analyses"].append({"fichier": filename, "type_analyse": "IA", "resume": extracted_data.get("resume", "N/A")})
        if "timeline_events" not in dossier_enquete: dossier_enquete["timeline_events"] = []
        for event in extracted_data.get("timeline", []):
            dossier_enquete["timeline_events"].append(event)
        typer.echo("--- [PHOENIX-CORRELATION] Phase 2: Enrichissement automatique des nouveaux IoCs...")
        for ioc_type, ioc_list in extracted_data.items():
            if ioc_type in dossier_enquete.get("iocs", {}) and isinstance(ioc_list, list):
                for ioc_value in ioc_list:
                    is_new = not any(d.get('valeur') == ioc_value for d in dossier_enquete["iocs"][ioc_type])
                    if is_new:
                        enrichment_data = enrichir_ioc_vt(ioc_type, ioc_value)
                        dossier_enquete["iocs"][ioc_type].append({"valeur": ioc_value, "source": filename, "enrichissement_vt": enrichment_data})
        typer.secho("--- [PHOENIX-CORRELATION] Dossier d'enquête mis à jour.", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"--- [PHOENIX-CORRELATION] Erreur lors de la mise à jour du dossier : {e} ---", fg=typer.colors.RED)
    return dossier_enquete

def generer_resume_executif_ia(dossier_enquete):
    typer.echo("--- [PHOENIX-REPORTING] Génération du résumé exécutif par l'IA...")
    contexte_simplifie = {"nom_du_cas": dossier_enquete.get("nom_du_cas"), "artefacts_analyses": [item['resume'] for item in dossier_enquete.get("artefacts_analyses", [])], "iocs": dossier_enquete.get("iocs")}
    prompt = f"Expert cybersécurité. Voici les données d'une enquête : {json.dumps(contexte_simplifie, indent=2)}. Rédige un résumé exécutif (3-5 phrases) qui synthétise la situation, les IoCs clés et la conclusion. Sois professionnel et factuel."
    return query_remote(prompt)

def creer_contenu_rapport(dossier_enquete, resume_executif):
    report_content = f"# Rapport d'Enquête : {dossier_enquete.get('nom_du_cas')}\n\n"
    report_content += f"**Date de génération :** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    report_content += f"**Date de création du cas :** {dossier_enquete.get('date_creation')}\n\n"
    report_content += "## Résumé Exécutif\n\n"
    report_content += f"{resume_executif}\n\n"
    report_content += "## Artefacts Analysés\n\n"
    for artefact in dossier_enquete.get("artefacts_analyses", []):
        report_content += f"- **Fichier :** `{artefact.get('fichier')}`\n  - **Résumé IA :** {artefact.get('resume')}\n"
    report_content += "\n## Indicateurs de Compromission (IoCs)\n\n"
    for ioc_type, ioc_list in dossier_enquete.get("iocs", {}).items():
        if ioc_list:
            report_content += f"### {ioc_type.upper()}\n\n"
            for ioc in ioc_list:
                report_content += f"- **Valeur :** `{ioc.get('valeur')}`\n  - **Source :** `{ioc.get('source')}`\n  - **Enrichissement VT :** {ioc.get('enrichissement_vt')}\n"
    report_content += "\n## Timeline des Événements\n\n"
    if dossier_enquete.get("timeline_events"):
        sorted_events = sorted(dossier_enquete.get("timeline_events", []), key=lambda x: x.get('timestamp', ''))
        for event in sorted_events:
            report_content += f"- **`{event.get('timestamp', 'N/A')}`** : {event.get('event')}\n"
    else:
        report_content += "_Aucun événement avec timestamp n'a été extrait des analyses._\n"
    return report_content

# --- COMMANDES TYPER ---
@app.command()
def nouvelle_enquete(nom_cas: str = typer.Argument(..., help="Le nom ou l'ID de la nouvelle enquête.")):
    dossier = {"nom_du_cas": nom_cas, "date_creation": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "artefacts_analyses": [], "timeline_events": [], "iocs": {"ips": [], "hashes": [], "domaines": []}}
    sauvegarder_session(dossier)
    typer.secho(f"--- [PHOENIX] Nouveau dossier d'enquête créé : {nom_cas} ---", fg=typer.colors.GREEN)

@app.command()
def resume_enquete():
    dossier_enquete = charger_session()
    if not dossier_enquete:
        typer.secho("Aucun dossier d'enquête sauvegardé.", fg=typer.colors.YELLOW); raise typer.Exit()
    typer.secho("\n--- Résumé du Dossier d'Enquête Actif ---", fg=typer.colors.CYAN)
    typer.echo(json.dumps(dossier_enquete, indent=2, ensure_ascii=False))

@app.command(help="Analyse un artefact, met à jour le dossier et enrichit les IoCs.")
def analyse(
    fichier: str = typer.Argument(..., help="Chemin du fichier."),
    question: str = typer.Argument(..., help="Tâche d'analyse."),
    filtre_id: int = typer.Option(None, "--filtre-id", "-id", help="Pour les EVTX, filtre par Event ID.")
):
    dossier_enquete = charger_session()
    if not dossier_enquete:
        typer.secho("Veuillez d'abord créer une enquête avec 'nouvelle-enquete'.", fg=typer.colors.RED); raise typer.Exit()
    resultat_analyse = analyse_fichier(fichier, question, dossier_enquete, filtre_id)
    typer.secho(f"\nPhoenix (Rapport pour {fichier}):", fg=typer.colors.BLUE)
    analyse_text = str(resultat_analyse.to_string() if isinstance(resultat_analyse, pd.DataFrame) else resultat_analyse)
    typer.echo(analyse_text)
    if not analyse_text.strip().startswith("Erreur:"):
        dossier_enquete_mis_a_jour = extraire_et_sauvegarder_conclusions(dossier_enquete, analyse_text, fichier)
        sauvegarder_session(dossier_enquete_mis_a_jour)
    else:
        typer.secho("--- Une erreur est survenue durant l'analyse. Corrélation annulée. ---", fg=typer.colors.YELLOW)

@app.command(help="Affiche une chronologie des événements de l'enquête.")
def afficher_timeline():
    dossier_enquete = charger_session()
    if not dossier_enquete or not dossier_enquete.get("timeline_events"):
        typer.secho("La timeline est vide. Analysez des fichiers pour la peupler.", fg=typer.colors.YELLOW); raise typer.Exit()
    typer.secho("\n--- Timeline de l'Enquête ---", fg=typer.colors.CYAN)
    sorted_events = sorted(dossier_enquete.get("timeline_events", []), key=lambda x: x.get('timestamp', ''))
    for event in sorted_events:
        typer.echo(f"**`{event.get('timestamp', 'N/A')}`** - {event.get('event', 'Description manquante.')}")

@app.command(help="Génère un rapport d'enquête complet au format Markdown.")
def generer_rapport(output_file: str = typer.Option(None, "--output", "-o", help="Nom du fichier de rapport (ex: rapport.md).")):
    dossier_enquete = charger_session()
    if not dossier_enquete:
        typer.secho("Aucun dossier d'enquête à rapporter.", fg=typer.colors.YELLOW); raise typer.Exit()
    resume_executif = generer_resume_executif_ia(dossier_enquete)
    report_content = creer_contenu_rapport(dossier_enquete, resume_executif)
    if not output_file:
        case_name_safe = dossier_enquete.get('nom_du_cas', 'sans_nom').replace(" ", "_")
        output_file = f"Rapport_{case_name_safe}_{datetime.datetime.now().strftime('%Y%m%d')}.md"
    typer.echo(f"--- [PHOENIX-REPORTING] Génération du rapport dans : {output_file} ---")
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        typer.secho(f"Rapport généré avec succès : {output_file}", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"Erreur lors de l'écriture du rapport : {e}", fg=typer.colors.RED)

# --- POINT D'ENTRÉE ---
if __name__ == "__main__":
    app()