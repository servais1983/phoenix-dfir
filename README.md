# 🔥 Phoenix - Assistant d'Analyse DFIR par IA

<div align="center">

![Phoenix Logo](https://img.shields.io/badge/🔥-Phoenix-orange?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-3.1-brightgreen?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![VirusTotal](https://img.shields.io/badge/VirusTotal-Integrated-red?style=for-the-badge)

**🚀 Un assistant interactif hybride pour l'investigation numérique avec enrichissement automatique via Threat Intelligence**

[🎯 Fonctionnalités](#-fonctionnalités-clés) • [⚡ Installation](#-installation-rapide) • [📖 Guide d'utilisation](#-guide-dutilisation) • [🔧 Configuration](#-configuration)

</div>

---

## 🎯 Vue d'ensemble

Phoenix est un assistant interactif en ligne de commande, spécialisé dans l'aide à l'investigation numérique et la réponse aux incidents (DFIR). Il est conçu pour être un **partenaire intelligent proactif** pour l'analyste, capable de traiter, d'analyser, de corréler et **d'enrichir automatiquement** des informations provenant de divers artefacts forensiques.

### 🧠 Philosophie IA Hybride + Threat Intelligence

Le projet repose sur une **approche d'IA hybride innovante**, combinant :
- 🏠 **Rapidité et confidentialité** d'un modèle de langage local (via Ollama) pour les tâches sensibles
- ☁️ **Puissance et capacités avancées** d'un modèle de pointe via API pour les tâches complexes
- 🌐 **Enrichissement automatique** des IoCs via des API de Threat Intelligence externes (VirusTotal)

## ✨ Fonctionnalités Clés (Version 3.1)

### 🔄 Moteur IA Hybride
- Utilise dynamiquement un modèle local (privé et rapide) et un modèle distant (puissant)
- Sélection automatique du meilleur modèle selon la tâche

### 🔍 Analyseur Polymorphe
- Détection automatique du type de fichier (`.csv`, `.json`, `.log`, `.txt`...)
- Application de la méthode d'analyse la plus pertinente pour chaque format

### 📂 Gestion d'Enquête
- Maintient un **"dossier d'enquête"** actif pour chaque session
- Conservation du contexte et des découvertes au fil du temps

### 🌐 **NOUVEAU** - Enrichissement Automatique via Threat Intelligence
- **Interrogation automatique** de l'API VirusTotal pour chaque nouvel IoC découvert
- **Contexte de réputation mondial** pour les IPs, domaines et hashes
- **Enrichissement proactif** sans intervention manuelle de l'analyste

### 🔗 Corrélation Autonome Enrichie
- Extraction automatique des **Indicateurs de Compromission (IoCs)** 
- **Archivage intelligent** dans le dossier d'enquête avec contexte d'enrichissement
- Corrélation avancée entre artefacts avec données de réputation

### 💻 Interface Ligne de Commande Améliorée
- Interface simple et directe pour gérer les enquêtes
- **Nouvelle commande `enrichir`** pour l'enrichissement manuel d'IoCs
- Rapports automatiquement enrichis avec données de Threat Intelligence

### 🧩 Architecture Modulaire Extensible
- Conçu pour être facilement extensible
- **Moteur d'enrichissement modulaire** pour intégrer nouvelles sources de renseignement
- Prêt pour de nouveaux analyseurs (ex: `.evtx`, ruches de registre...)

## 🏗️ Architecture du Système v3.1

```
Phoenix v3.1 - L'Enquêteur Proactif
├── 🎯 Boucle Principale (main)
│   └── Cœur interactif qui écoute les commandes
├── 🔀 Aiguilleur d'Analyse (analyse_fichier)
│   └── Identification du type de fichier et routage
├── ⚙️ Gestionnaires Spécialisés
│   ├── handle_csv (Pandas + IA)
│   ├── handle_json (Structure + IA)
│   └── handle_generic_text (IA locale)
├── 🌐 **NOUVEAU** Moteur d'Enrichissement (enrichir_ioc_vt)
│   └── Communication avec API VirusTotal
├── 🧠 Mémoire d'Enquête (dossier_enquete)
│   └── État global de l'investigation + IoCs enrichis
└── 🔍 Moteur d'Extraction Intelligent
    └── IA "méta" pour extraire et enrichir automatiquement
```

## ⚡ Installation Rapide

### 📋 Prérequis
- ![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python) Python 3.9 ou supérieur
- ![Git](https://img.shields.io/badge/Git-orange?logo=git) Git (optionnel)
- Terminal ou invite de commande

### 🚀 Installation

1. **Clonez le projet**
```bash
git clone https://github.com/servais1983/phoenix-dfir.git
cd phoenix-dfir
```

2. **Créez un environnement virtuel**
```bash
# Créez l'environnement
python -m venv venv

# Activez-le
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
```

3. **Installez les dépendances**
```bash
pip install -r requirements.txt
```

## 🔧 Configuration

### 🏠 Configuration de l'IA Locale (Ollama)
1. Téléchargez et installez [Ollama](https://ollama.com)
2. Lancez Ollama (il tournera en arrière-plan)
3. Téléchargez le modèle optimisé :
```bash
ollama pull phi3:mini
```

### 🔑 Configuration des Clés API

#### **Google AI Studio**
1. Obtenez une clé API gratuite depuis [Google AI Studio](https://aistudio.google.com)

#### **🆕 VirusTotal API** 
1. Créez un compte gratuit sur [VirusTotal](https://virustotal.com)
2. Récupérez votre clé API dans les paramètres de votre profil

#### **Configuration dans le code**
Ouvrez le fichier `phoenix.py` et remplacez les placeholders :

```python
API_KEY_GOOGLE = "VOTRE_CLE_API_GOOGLE_ICI"
API_KEY_VT = "VOTRE_CLE_API_VIRUSTOTAL_ICI"
```

## 📖 Guide d'Utilisation

### 🎮 Lancement
```bash
python phoenix.py
```

### 📝 Commandes Disponibles

| Commande | Description | Exemple |
|----------|-------------|---------|
| `nouvelle_enquete <nom>` | 🆕 Démarre une nouvelle investigation | `nouvelle_enquete CASE-2025-06-26` |
| `resume_enquete` | 📋 Affiche le résumé complet avec IoCs enrichis | `resume_enquete` |
| `analyse <fichier> "<question>"` | 🔍 Analyse + enrichissement automatique | `analyse auth.log "IPs suspectes ?"` |
| `enrichir <type> <valeur>` | 🌐 **NOUVEAU** - Enrichissement manuel d'IoC | `enrichir ip 8.8.8.8` |
| `quitter` | 🚪 Arrête Phoenix | `quitter` |

### 🎯 Types d'IoCs Supportés (avec enrichissement automatique)
- **`ip`** : Adresses IP (réputation VirusTotal)
- **`domaine`** : Noms de domaines (analyse DNS et réputation)
- **`hash`** : Hachages de fichiers (détection malware)

## 🔥 Exemple de Scénario d'Enquête v3.1

```bash
# 🚀 Lancement de Phoenix
python phoenix.py

==================================================
Bienvenue dans PHOENIX v3.1 - L'Enquêteur Proactif
==================================================

# 🆕 Nouvelle enquête
Vous: nouvelle_enquete Intrusion-SSH-ServeurWeb

--- [PHOENIX] Nouveau dossier d'enquête créé : Intrusion-SSH-ServeurWeb ---

# 🔍 Analyse avec enrichissement automatique
Vous: analyse samples/auth.log "cherche toutes les IPs liées à des échecs de connexion"

--- [Text Handler] Analyse de samples/auth.log ---
--- [PHOENIX-CORE] Utilisation du modèle local: phi3:mini...
# ... Phoenix retourne son analyse textuelle ...

--- [PHOENIX-CORRELATION] Phase 1: Extraction des IoCs...
--- [PHOENIX-AUGMENTED] Utilisation du modèle distant: gemini-1.5-flash...
--- [PHOENIX-CORRELATION] Phase 2: Enrichissement automatique des nouveaux IoCs...
--- [PHOENIX-THREATINTEL] Enrichissement de '103.207.39.45' via VirusTotal...
--- [PHOENIX-CORRELATION] Dossier d'enquête mis à jour avec les infos enrichies. ---

# 📋 Résumé avec données enrichies
Vous: resume_enquete

--- [PHOENIX] Résumé du Dossier d'Enquête Actif ---
{'artefacts_analyses': [{'fichier': 'samples/auth.log',
                        'resume': 'Des tentatives de connexion échouées détectées '
                                  "depuis l'IP '103.207.39.45'."}],
 'date_creation': '2025-06-26 15:30:00',
 'iocs': {'domaines': [],
          'hashes': [],
          'ips': [{'enrichissement_vt': 'Rapport VirusTotal - '
                                        'Propriétaire: VIETNAM POSTS AND TELECOMMUNICATIONS GROUP | '
                                        'Score Malveillant: 0/84',
                  'source': 'samples/auth.log',
                  'valeur': '103.207.39.45'}]},
 'nom_du_cas': 'Intrusion-SSH-ServeurWeb'}

# 🌐 Enrichissement manuel d'un IoC supplémentaire
Vous: enrichir ip 8.8.8.8

--- [PHOENIX-THREATINTEL] Enrichissement de '8.8.8.8' via VirusTotal...
Enrichissement terminé pour 8.8.8.8
Résultat: Rapport VirusTotal - Propriétaire: GOOGLE | Score: 1/84 moteurs de détection

# 🚪 Fin de session
Vous: quitter
```

## 🗂️ Fichiers d'Exemple

Le dossier `samples/` contient des fichiers d'exemple pour tester Phoenix :
- `auth.log` : Logs d'authentification SSH avec IPs suspectes
- `firewall_logs.csv` : Logs de pare-feu au format CSV
- `report.json` : Rapport d'incident au format JSON

## 🛣️ Feuille de Route

### 🔜 Prochaines Fonctionnalités v4.0
- **[Analyseurs]** Support des formats binaires (`.evtx`, Ruches de Registre, Prefetch)
- **[Reporting]** Export automatique en Markdown avec `generer_rapport`
- **[Visualisation]** Intégration de matplotlib pour créer des timelines d'événements
- **[Multi-Sources]** Intégration d'APIs supplémentaires (AlienVault OTX, AbuseIPDB)
- **[Intelligence]** Corrélation avancée utilisant le graphe de réputation des IoCs

### 🎯 Vision Long Terme
Faire de Phoenix une **plateforme d'investigation proactive** incontournable pour la communauté DFIR mondiale.

## 🤝 Contribution

Les contributions sont les bienvenues ! 

1. **Fork** le projet
2. **Créez** votre branche de fonctionnalité (`git checkout -b feature/AmazingFeature`)
3. **Committez** vos changements (`git commit -m 'Add some AmazingFeature'`)
4. **Push** vers la branche (`git push origin feature/AmazingFeature`)
5. **Ouvrez** une Pull Request

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 🏆 Reconnaissance

Créé avec ❤️ pour la communauté DFIR - **Version 3.1 avec enrichissement automatique via Threat Intelligence**

---

<div align="center">

**[⭐ N'oubliez pas de mettre une étoile si ce projet vous aide !](https://github.com/servais1983/phoenix-dfir)**

*Phoenix v3.1 - L'enquêteur qui enrichit automatiquement vos découvertes* 🔥🌐

</div>