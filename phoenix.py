# Imports et Configuration
import ollama
import google.generativeai as genai
import pandas as pd
import json
import os
import datetime
import pprint
import requests

# --- CONFIGURATION ---
MODEL_LOCAL = 'phi3:mini' 
MODEL_REMOTE = 'gemini-1.5-flash'
API_KEY_GOOGLE = "VOTRE_CLE_API_GOOGLE_ICI"
API_KEY_VT = "VOTRE_CLE_API_VIRUSTOTAL_ICI"

# --- MÉMOIRE DE TRAVAIL ---
dossier_enquete = {}

# --- FONCTIONS CÉRÉBRALES ---
def query_local(prompt):
    print(f"\n--- [PHOENIX-CORE] Utilisation du modèle local: {MODEL_LOCAL}...")
    try:
        response = ollama.chat(model=MODEL_LOCAL, messages=[{'role': 'user', 'content': prompt}])
        return response['message']['content']
    except Exception as e:
        return f"Erreur de connexion au Coeur Phoenix (Ollama).\nDétail: {e}"

def query_remote(prompt):
    print(f"\n--- [PHOENIX-AUGMENTED] Utilisation du modèle distant: {MODEL_REMOTE}...")
    try:
        genai.configure(api_key=API_KEY_GOOGLE)
        model = genai.GenerativeModel(MODEL_REMOTE)
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Erreur de connexion au Cerveau Augmenté.\nDétail: {e}"

# --- NOUVEAU: MOTEUR D'ENRICHISSEMENT THREAT INTELLIGENCE ---
def enrichir_ioc_vt(ioc_type, ioc_value):
    print(f"\n--- [PHOENIX-THREATINTEL] Enrichissement de '{ioc_value}' via VirusTotal...")
    
    # Normalisation du type d'IoC (enlever le 's' final si présent)
    normalized_ioc_type = ioc_type.rstrip('s')
    
    # Construction de l'URL selon le type
    if normalized_ioc_type == 'ip':
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
    elif normalized_ioc_type == 'domaine':
        url = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
    elif normalized_ioc_type == 'hash':
        url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
    else:
        return "Type d'IoC non supporté pour l'enrichissement."
    
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY_VT
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        # Extraction des informations pertinentes
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious_score = stats.get("malicious", 0)
        total_engines = sum(stats.values()) if stats else 0
        owner = attributes.get("as_owner", "N/A")
        country = attributes.get("country", "N/A")
        
        return f"Rapport VirusTotal ({country}) - Propriétaire: {owner} | Score Malveillant: {malicious_score}/{total_engines}"
        
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            return f"Info: '{ioc_value}' non trouvé dans la base VirusTotal."
        return f"Erreur HTTP VirusTotal: {e}"
    except Exception as e:
        return f"Erreur durant l'enrichissement VirusTotal: {e}"

# --- GESTIONNAIRES DE FICHIERS SPÉCIALISÉS ---
def handle_csv(filename, user_query):
    print(f"--- [CSV Handler] Analyse de {filename} ---")
    df = pd.read_csv(filename)
    column_names = ", ".join(df.columns)
    context_info = "Pour t'aider, voici quelques informations sur les données : "
    for col in df.select_dtypes(include=['object']).columns:
        if df[col].nunique() < 10:
            unique_values = df[col].unique().tolist()
            context_info += f"La colonne '{col}' contient les valeurs possibles : {unique_values}. "
    code_generation_prompt = f"""Tu es un expert DFIR utilisant Pandas. Un DataFrame 'df' a les colonnes [{column_names}]. {context_info} La demande est : "{user_query}". Écris une seule ligne de code Python pour filtrer le DataFrame. Le résultat doit être dans la variable 'resultat'."""
    generated_code = query_remote(code_generation_prompt)
    cleaned_code = generated_code.replace("```python", "").replace("```", "").strip()
    print(f"--- [PHOENIX-AI-DEV] Code généré : {cleaned_code} ---")
    exec_scope = {'df': df, 'pd': pd}
    exec(cleaned_code, exec_scope)
    return exec_scope.get('resultat', "Le code n'a pas retourné de 'resultat'.")

def handle_json(filename, user_query):
    print(f"--- [JSON Handler] Analyse de {filename} ---")
    with open(filename, 'r', encoding='utf-8') as f:
        data = json.load(f)
    structure = list(data.keys())
    analysis_prompt = f"Tu es un analyste DFIR. Voici un extrait de données d'un fichier JSON. Les clés principales sont : {structure}. La demande de l'utilisateur est : \"{user_query}\". Fais une analyse et réponds à la demande. Contenu (extrait) : {str(data)[:2000]}"
    return query_local(analysis_prompt)

def handle_generic_text(filename, user_query):
    print(f"--- [Text Handler] Analyse de {filename} ---")
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    analysis_prompt = f"Tu es un analyste DFIR. Voici le contenu d'un fichier nommé '{filename}'. La demande de l'utilisateur est : \"{user_query}\". Analyse ce contenu en détail et réponds. Contenu :\n\n---\n{content}\n---"
    return query_local(analysis_prompt)

def analyse_fichier(filename, user_query):
    try:
        _, extension = os.path.splitext(filename.lower())
        if extension == '.csv':
            return handle_csv(filename, user_query)
        elif extension == '.json':
            return handle_json(filename, user_query)
        elif extension in ['.log', '.txt', '.xml', '.ps1', '.bat', '.sh']:
            return handle_generic_text(filename, user_query)
        else:
            print(f"Phoenix ne sait pas encore comment analyser les fichiers '{extension}'. Tentative d'analyse texte générique...")
            return handle_generic_text(filename, user_query)
    except FileNotFoundError:
        return f"Erreur: Le fichier '{filename}' est introuvable."
    except Exception as e:
        return f"Erreur inattendue durant l'analyse : {e}"

# --- FONCTION D'EXTRACTION ET ENRICHISSEMENT AUTOMATIQUE ---
def extraire_et_sauvegarder_conclusions(analyse_text, filename):
    global dossier_enquete
    print("\n--- [PHOENIX-CORRELATION] Phase 1: Extraction des IoCs...")
    extraction_prompt = f"""Tu es un robot d'extraction d'information pour une enquête DFIR. Lis le rapport d'analyse suivant et extrais les informations clés. Réponds UNIQUEMENT avec un objet JSON. Le format doit être :{{"ips": ["ip1", ...], "hashes": ["hash1", ...], "domaines": ["domaine1.com", ...], "resume": "Un résumé très court et factuel de la conclusion principale."}} Si une catégorie est vide, laisse une liste vide. Rapport d'analyse :\n---\n{analyse_text}\n---"""
    json_response_str = query_remote(extraction_prompt)
    cleaned_json_str = json_response_str.replace("```json", "").replace("```", "").strip()
    try:
        extracted_data = json.loads(cleaned_json_str)
        if "artefacts_analyses" not in dossier_enquete: 
            dossier_enquete["artefacts_analyses"] = []
        dossier_enquete["artefacts_analyses"].append({"fichier": filename, "resume": extracted_data.get("resume", "Pas de résumé fourni.")})

        print("--- [PHOENIX-CORRELATION] Phase 2: Enrichissement automatique des nouveaux IoCs...")
        for ioc_type, ioc_list in extracted_data.items():
            if ioc_type in dossier_enquete.get("iocs", {}) and isinstance(ioc_list, list):
                for ioc_value in ioc_list:
                    # Vérifier si l'IoC est nouveau (pas déjà dans le dossier)
                    is_new = not any(d.get('valeur') == ioc_value for d in dossier_enquete["iocs"][ioc_type])
                    if is_new:
                        enrichment_data = enrichir_ioc_vt(ioc_type, ioc_value)
                        dossier_enquete["iocs"][ioc_type].append({
                            "valeur": ioc_value, 
                            "source": filename, 
                            "enrichissement_vt": enrichment_data
                        })
        print("--- [PHOENIX-CORRELATION] Dossier d'enquête mis à jour avec les infos enrichies. ---")
    except json.JSONDecodeError:
        print("--- [PHOENIX-CORRELATION] Erreur: L'IA n'a pas retourné un JSON valide. Ajout automatique échoué. ---")
    except Exception as e:
        print(f"--- [PHOENIX-CORRELATION] Erreur inattendue lors de la mise à jour du dossier : {e} ---")

# --- BOUCLE PRINCIPALE ---
def main():
    global dossier_enquete
    print("="*50)
    print("Bienvenue dans PHOENIX v3.1 - L'Enquêteur Proactif")
    print("Commandes: nouvelle_enquete, resume_enquete, analyse, enrichir, quitter")
    print("="*50)

    while True:
        user_prompt = input("\nVous: ")
        parts = user_prompt.split(" ", 2)
        command = parts[0].lower()
        
        if command in ["quitter", "stop", "exit"]:
            print("\n--- [PHOENIX] Système arrêté. ---")
            break
        elif command == "nouvelle_enquete":
            if len(parts) > 1:
                case_name = parts[1]
                dossier_enquete = {
                    "nom_du_cas": case_name, 
                    "date_creation": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                    "artefacts_analyses": [], 
                    "iocs": {"ips": [], "hashes": [], "domaines": []}
                }
                print(f"--- [PHOENIX] Nouveau dossier d'enquête créé : {case_name} ---")
            else:
                print("\nPhoenix Aide: Format -> nouvelle_enquete <nom_du_cas>")
        elif command == "resume_enquete":
            if not dossier_enquete:
                print("\n--- [PHOENIX] Aucun dossier d'enquête n'est actuellement ouvert. ---")
            else:
                print("\n--- [PHOENIX] Résumé du Dossier d'Enquête Actif ---")
                pprint.pprint(dossier_enquete)
        elif command == "enrichir":
            if not dossier_enquete: 
                print("\n--- [PHOENIX] Veuillez d'abord créer une enquête avec 'nouvelle_enquete'. ---")
            elif len(parts) == 3:
                ioc_type = parts[1].lower()
                ioc_value = parts[2]
                if ioc_type in ['ip', 'domaine', 'hash']:
                    enrichment_result = enrichir_ioc_vt(ioc_type, ioc_value)
                    print(f"Enrichissement terminé pour {ioc_value}")
                    print(f"Résultat: {enrichment_result}")
                else: 
                    print(f"\nPhoenix Aide: Type d'IoC non valide. Types valides : ip, domaine, hash")
            else: 
                print("\nPhoenix Aide: Format -> enrichir <type> <valeur>")
        elif command == "analyse":
            if not dossier_enquete: 
                print("\n--- [PHOENIX] Veuillez d'abord créer une enquête avec 'nouvelle_enquete'. ---")
            elif len(parts) == 3 and parts[2].startswith('"') and parts[2].endswith('"'):
                filename = parts[1]
                user_query = parts[2].strip('"')
                resultat_analyse = analyse_fichier(filename, user_query)
                print(f"\nPhoenix (Rapport pour {filename}):")
                if isinstance(resultat_analyse, pd.DataFrame):
                    analyse_text = resultat_analyse.to_string()
                else:
                    analyse_text = str(resultat_analyse)
                print(analyse_text)
                if "Erreur:" not in analyse_text:
                    extraire_et_sauvegarder_conclusions(analyse_text, filename)
            else: 
                print("\nPhoenix Aide: Format -> analyse <fichier> \"votre question\"")
        else:
            response = query_local(user_prompt)
            print(f"\nPhoenix:\n{response}")

if __name__ == "__main__":
    main()