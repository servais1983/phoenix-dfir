# Imports et Configuration
import ollama, google.generativeai as genai, pandas as pd, json, os, datetime, pprint, requests

# --- CONFIGURATION ---
MODEL_LOCAL = 'phi3:mini' 
MODEL_REMOTE = 'gemini-1.5-flash'
API_KEY_GOOGLE = "AIzaSyCIC-2Uc_O_Q-lB_FlTyJenT2XA3PFeYKM"
API_KEY_VT = "3136c308ce9db10a8dadb4f42c4032009b031598fe5706d2c0337ddf8c8acb8d"

# --- MÉMOIRE DE TRAVAIL ---
dossier_enquete = {}

# --- FONCTIONS CÉRÉBRALES ---
def query_local(prompt):
    # ... (identique) ...
    print(f"\n--- [PHOENIX-CORE] Utilisation du modèle local: {MODEL_LOCAL}...")
    try:
        response = ollama.chat(model=MODEL_LOCAL, messages=[{'role': 'user', 'content': prompt}])
        return response['message']['content']
    except Exception as e:
        return f"Erreur de connexion au Coeur Phoenix (Ollama).\nDétail: {e}"

def query_remote(prompt):
    # ... (identique) ...
    print(f"\n--- [PHOENIX-AUGMENTED] Utilisation du modèle distant: {MODEL_REMOTE}...")
    try:
        genai.configure(api_key=API_KEY_GOOGLE)
        model = genai.GenerativeModel(MODEL_REMOTE)
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Erreur de connexion au Cerveau Augmenté.\nDétail: {e}"

def enrichir_ioc_vt(ioc_type, ioc_value):
    # ... (identique, avec la correction singulier/pluriel) ...
    print(f"\n--- [PHOENIX-THREATINTEL] Enrichissement de '{ioc_value}' via VirusTotal...")
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

# --- GESTIONNAIRES DE FICHIERS (identiques) ---
def handle_csv(filename, user_query):
    # ... (identique) ...
    print(f"--- [CSV Handler] Analyse de {filename} ---")
    df = pd.read_csv(filename)
    column_names = ", ".join(df.columns)
    context_info = "Pour t'aider, voici des infos : "
    for col in df.select_dtypes(include=['object']).columns:
        if df[col].nunique() < 10:
            unique_values = df[col].unique().tolist()
            context_info += f"La colonne '{col}' contient les valeurs : {unique_values}. "
    code_generation_prompt = f"""Tu es un expert DFIR utilisant Pandas. Un DataFrame 'df' a les colonnes [{column_names}]. {context_info} La demande est : "{user_query}". Écris une seule ligne de code Python pour filtrer 'df'. Le résultat doit être dans la variable 'resultat'."""
    generated_code = query_remote(code_generation_prompt)
    cleaned_code = generated_code.replace("```python", "").replace("```", "").strip()
    print(f"--- [PHOENIX-AI-DEV] Code généré : {cleaned_code} ---")
    exec_scope = {'df': df, 'pd': pd}
    exec(cleaned_code, exec_scope)
    return exec_scope.get('resultat', "Le code n'a pas retourné de 'resultat'.")

def handle_json(filename, user_query):
    # ... (identique) ...
    print(f"--- [JSON Handler] Analyse de {filename} ---")
    with open(filename, 'r', encoding='utf-8') as f:
        data = json.load(f)
    structure = list(data.keys())
    analysis_prompt = f"Tu es un analyste DFIR. Un fichier JSON a les clés principales : {structure}. La demande est : \"{user_query}\". Analyse et réponds. Contenu (extrait) : {str(data)[:2000]}"
    return query_local(analysis_prompt)

def handle_generic_text(filename, user_query):
    # ... (identique) ...
    print(f"--- [Text Handler] Analyse de {filename} ---")
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    analysis_prompt = f"Tu es un analyste DFIR. Un fichier nommé '{filename}' contient ceci. La demande est : \"{user_query}\". Analyse et réponds. Contenu :\n\n---\n{content}\n---"
    return query_local(analysis_prompt)

def analyse_fichier(filename, user_query):
    # ... (identique) ...
    try:
        _, extension = os.path.splitext(filename.lower())
        if extension == '.csv':
            return handle_csv(filename, user_query)
        elif extension == '.json':
            return handle_json(filename, user_query)
        elif extension in ['.log', '.txt', '.xml', '.ps1', '.bat', '.sh']:
            return handle_generic_text(filename, user_query)
        else:
            print(f"Format '{extension}' non spécialisé. Tentative d'analyse texte générique...")
            return handle_generic_text(filename, user_query)
    except FileNotFoundError:
        return f"Erreur: Le fichier '{filename}' est introuvable."
    except Exception as e:
        return f"Erreur inattendue durant l'analyse : {e}"

# --- FONCTION D'EXTRACTION PROACTIVE (MISE À JOUR) ---
def extraire_et_sauvegarder_conclusions(analyse_text, filename):
    global dossier_enquete
    print("\n--- [PHOENIX-CORRELATION] Phase 1: Extraction des IoCs...")
    extraction_prompt = f"""Tu es un robot d'extraction d'info DFIR. Lis le rapport suivant. Extrais les infos clés. Réponds UNIQUEMENT en JSON. Format :{{"ips": ["ip1", ...], "hashes": [], "domaines": [], "resume": "Résumé court."}}. Si vide, laisse une liste vide. Rapport :\n---\n{analyse_text}\n---"""
    json_response_str = query_remote(extraction_prompt)
    cleaned_json_str = json_response_str.replace("```json", "").replace("```", "").strip()
    try:
        extracted_data = json.loads(cleaned_json_str)
        dossier_enquete["artefacts_analyses"].append({"fichier": filename, "resume": extracted_data.get("resume", "N/A")})

        print("--- [PHOENIX-CORRELATION] Phase 2: Enrichissement automatique des nouveaux IoCs...")
        for ioc_type, ioc_list in extracted_data.items():
            if ioc_type in dossier_enquete["iocs"] and isinstance(ioc_list, list):
                for ioc_value in ioc_list:
                    is_new = not any(d.get('valeur') == ioc_value for d in dossier_enquete["iocs"][ioc_type])
                    if is_new:
                        enrichment_data = enrichir_ioc_vt(ioc_type, ioc_value)
                        dossier_enquete["iocs"][ioc_type].append({"valeur": ioc_value, "source": filename, "enrichissement_vt": enrichment_data})
        print("--- [PHOENIX-CORRELATION] Dossier d'enquête mis à jour avec les infos enrichies. ---")
    except Exception as e:
        print(f"--- [PHOENIX-CORRELATION] Erreur lors de la mise à jour du dossier : {e} ---")

# --- BOUCLE PRINCIPALE FINALE ---
def main():
    global dossier_enquete
    print("="*50)
    print("Bienvenue dans PHOENIX v3.1 - L'Enquêteur Proactif")
    print("Commandes: nouvelle_enquete, resume_enquete, analyse, quitter")
    print("="*50)

    while True:
        user_prompt = input("\nVous: ")
        parts = user_prompt.split(" ", 2)
        command = parts[0].lower()

        if command in ["quitter", "stop", "exit"]:
            print("\n--- [PHOENIX] Système arrêté. ---"); break
        elif command == "nouvelle_enquete":
            case_name = parts[1] if len(parts) > 1 else "NouveauCas"
            dossier_enquete = {"nom_du_cas": case_name, "date_creation": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "artefacts_analyses": [], "iocs": {"ips": [], "hashes": [], "domaines": []}}
            print(f"--- [PHOENIX] Nouveau dossier d'enquête créé : {case_name} ---")
        elif command == "resume_enquete":
            if not dossier_enquete: print("\n--- [PHOENIX] Aucun dossier ouvert. ---")
            else:
                print("\n--- [PHOENIX] Résumé du Dossier d'Enquête Actif ---")
                pprint.pprint(dossier_enquete)
        elif command == "analyse":
            if not dossier_enquete: print("\n--- [PHOENIX] Créez une enquête d'abord. ---")
            elif len(parts) == 3 and parts[2].startswith('"') and parts[2].endswith('"'):
                filename, user_query = parts[1], parts[2].strip('"')
                resultat_analyse = analyse_fichier(filename, user_query)
                print(f"\nPhoenix (Rapport pour {filename}):")
                analyse_text = str(resultat_analyse.to_string() if isinstance(resultat_analyse, pd.DataFrame) else resultat_analyse)
                print(analyse_text)
                if "Erreur:" not in analyse_text:
                    extraire_et_sauvegarder_conclusions(analyse_text, filename)
            else: print("\nPhoenix Aide: Format -> analyse <fichier> \"votre question\"")
        else:
            print("\nPhoenix Aide: Commande non reconnue. Commandes valides: nouvelle_enquete, resume_enquete, analyse, quitter.")

if __name__ == "__main__":
    main()