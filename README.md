# 🔥 Phoenix - Assistant d'Analyse DFIR par IA

<div align="center">

![Phoenix Logo](https://img.shields.io/badge/🔥-Phoenix-orange?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-4.0_FINAL-brightgreen?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![VirusTotal](https://img.shields.io/badge/VirusTotal-Integrated-red?style=for-the-badge)
![CLI](https://img.shields.io/badge/Typer-CLI_Framework-purple?style=for-the-badge)
![EVTX](https://img.shields.io/badge/EVTX-Windows_Logs-blue?style=for-the-badge)

**🚀 Plateforme professionnelle d'investigation DFIR avec IA hybride, enrichissement automatique et interface CLI moderne**

[🎯 Fonctionnalités](#-fonctionnalités-clés) • [⚡ Installation](#-installation-rapide) • [📖 Guide d'utilisation](#-guide-dutilisation) • [🔧 Configuration](#-configuration)

</div>

---

## 🎯 Vue d'ensemble

Phoenix est une **plateforme professionnelle d'investigation DFIR** alimentée par l'IA, conçue pour être le partenaire ultime des analystes en cybersécurité. Cette version finale combine une architecture hybride d'IA, un enrichissement automatique via Threat Intelligence, et une interface CLI moderne pour une expérience d'investigation de niveau entreprise.

### 🧠 Architecture IA Hybride + Threat Intelligence + CLI Moderne

Le projet repose sur une **approche d'IA hybride révolutionnaire**, combinant :
- 🏠 **Rapidité et confidentialité** d'un modèle de langage local (Ollama) pour les données sensibles
- ☁️ **Puissance et analyse complexe** d'un modèle distant (Gemini) pour les tâches avancées
- 🌐 **Enrichissement proactif** via APIs de Threat Intelligence (VirusTotal)
- 💻 **Interface CLI professionnelle** avec Typer pour un usage en production

## ✨ Fonctionnalités Clés (Version 4.0 FINALE)

### 🖥️ **NOUVEAU** - Interface CLI Professionnelle avec Typer
- **Interface moderne** avec coloration syntaxique et aide contextuelle
- **Commandes structurées** avec arguments et options avancées
- **Gestion d'erreurs robuste** avec messages explicites
- **Expérience utilisateur optimisée** pour un usage en production

### 📁 **NOUVEAU** - Gestion de Session Persistante
- **Sauvegarde automatique** des enquêtes en cours dans `session_enquete.json`
- **Reprise d'enquête** après redémarrage du système
- **Historique complet** des analyses et découvertes
- **Intégrité des données** garantie

### 🔍 **NOUVEAU** - Analyseur EVTX Avancé
- **Support natif** des logs Windows au format `.evtx`
- **Filtrage par Event ID** pour des analyses ciblées
- **Parsing XML optimisé** avec gestion des erreurs
- **Extraction intelligente** d'événements de sécurité critiques

### ⏰ **NOUVEAU** - Timeline Automatique
- **Extraction automatique** des timestamps depuis tous les artefacts
- **Chronologie consolidée** des événements d'incident
- **Visualisation temporelle** pour comprendre la séquence d'attaque
- **Corrélation temporelle** entre différents artefacts

### 📝 **NOUVEAU** - Génération de Rapports Professionnels
- **Rapports Markdown** avec résumé exécutif généré par IA
- **Export automatique** avec nomenclature standardisée
- **Synthèse intelligente** des IoCs et événements
- **Prêt pour présentation** aux équipes dirigeantes

### 📊 **NOUVEAU** - CSV Contextuel Intelligent
- **Analyse contextuelle** utilisant les IoCs de l'enquête en cours
- **Génération de code Pandas** optimisée et sécurisée
- **Validation syntaxique** automatique du code généré
- **Corrélation croisée** entre artefacts CSV

### 🔄 Moteur IA Hybride (Amélioré)
- Utilise dynamiquement un modèle local (privé et rapide) et un modèle distant (puissant)
- Sélection automatique du meilleur modèle selon la tâche

### 🌐 Enrichissement Automatique via Threat Intelligence
- **Interrogation automatique** de l'API VirusTotal pour chaque nouvel IoC découvert
- **Contexte de réputation mondial** pour les IPs, domaines et hashes
- **Enrichissement proactif** sans intervention manuelle de l'analyste

### 🔗 Corrélation Autonome Enrichie
- Extraction automatique des **Indicateurs de Compromission (IoCs)** 
- **Archivage intelligent** dans le dossier d'enquête avec contexte d'enrichissement
- Corrélation avancée entre artefacts avec données de réputation

### 🧩 Architecture Modulaire Extensible
- Conçu pour être facilement extensible
- **Moteur d'enrichissement modulaire** pour intégrer nouvelles sources de renseignement
- **Gestionnaires de fichiers spécialisés** pour chaque format

## 🏗️ Architecture du Système v4.0

```
Phoenix v4.0 FINAL - Plateforme DFIR Professionnelle
├── 🖥️ Interface CLI Typer
│   ├── Commandes structurées avec aide contextuelle
│   ├── Gestion d'erreurs et validation d'entrée
│   └── Messages colorés et formatés
├── 📁 Gestionnaire de Session
│   ├── Sauvegarde/chargement automatique JSON
│   ├── Persistance entre redémarrages
│   └── Intégrité des données d'enquête
├── 🔀 Aiguilleur d'Analyse Étendu
│   ├── Support EVTX avec filtrage Event ID
│   ├── CSV contextuel avec IoCs existants
│   ├── JSON structuré et texte générique
│   └── Validation et gestion d'erreurs robuste
├── ⏰ **NOUVEAU** Moteur de Timeline
│   ├── Extraction automatique de timestamps
│   ├── Chronologie consolidée d'événements
│   └── Corrélation temporelle inter-artefacts
├── 🌐 Moteur d'Enrichissement VirusTotal
│   ├── Enrichissement automatique des IoCs
│   ├── Cache et optimisation des requêtes
│   └── Gestion des erreurs API
├── 📝 **NOUVEAU** Générateur de Rapports
│   ├── Résumé exécutif par IA
│   ├── Export Markdown professionnel
│   └── Nomenclature standardisée
├── 🧠 Mémoire d'Enquête Persistante
│   ├── État global avec timeline
│   ├── IoCs enrichis et contextualisés
│   └── Historique des analyses
└── 🔍 Moteur d'Extraction Intelligent
    ├── Extraction IoCs + timestamps
    ├── Corrélation automatique
    └── Enrichissement proactif
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

#### **VirusTotal API** 
1. Créez un compte gratuit sur [VirusTotal](https://virustotal.com)
2. Récupérez votre clé API dans les paramètres de votre profil

#### **Configuration dans le code**
Ouvrez le fichier `phoenix.py` et remplacez les placeholders :

```python
API_KEY_GOOGLE = "VOTRE_CLE_API_GOOGLE_ICI"
API_KEY_VT = "VOTRE_CLE_API_VIRUSTOTAL_ICI"
```

## 📖 Guide d'Utilisation

### 🎮 Lancement et Aide
```bash
# Lancement avec aide générale
python phoenix.py --help

# Aide spécifique pour une commande
python phoenix.py analyse --help
```

### 📝 Commandes Disponibles v4.0

| Commande | Description | Exemple |
|----------|-------------|---------|
| `nouvelle-enquete <nom>` | 🆕 Crée une nouvelle investigation | `python phoenix.py nouvelle-enquete "CASE-2025-06-26"` |
| `resume-enquete` | 📋 Affiche le résumé complet avec IoCs enrichis | `python phoenix.py resume-enquete` |
| `analyse <fichier> "<question>" [--filtre-id]` | 🔍 Analyse + enrichissement automatique | `python phoenix.py analyse auth.log "IPs suspectes"` |
| `afficher-timeline` | ⏰ **NOUVEAU** - Chronologie des événements | `python phoenix.py afficher-timeline` |
| `generer-rapport [--output]` | 📝 **NOUVEAU** - Rapport professionnel | `python phoenix.py generer-rapport -o rapport.md` |

### 🎯 Exemples d'Usage Avancé

#### **Analyse EVTX avec filtre Event ID**
```bash
python phoenix.py analyse Security.evtx "logons suspects" --filtre-id 4625
```

#### **Analyse CSV contextuelle**
```bash
# Les IPs déjà découvertes dans l'enquête seront automatiquement utilisées comme contexte
python phoenix.py analyse network_logs.csv "activité des IPs suspectes"
```

#### **Génération de rapport avec nom personnalisé**
```bash
python phoenix.py generer-rapport --output "Rapport_Incident_Critique_20250626.md"
```

## 🔥 Exemple de Workflow d'Investigation v4.0

```bash
# 🚀 Nouvelle investigation
python phoenix.py nouvelle-enquete "INCIDENT-RANSOMWARE-2025"

# 🔍 Analyse des logs d'authentification
python phoenix.py analyse auth.log "échecs de connexion et tentatives de brute force"

# 💻 Analyse des logs système Windows (avec filtre)
python phoenix.py analyse System.evtx "événements de démarrage suspects" --filtre-id 7045

# 📊 Analyse des logs réseau (avec contexte automatique des IPs découvertes)
python phoenix.py analyse firewall_logs.csv "trafic réseau des IPs malveillantes"

# ⏰ Visualisation de la chronologie
python phoenix.py afficher-timeline

# 📋 État de l'enquête
python phoenix.py resume-enquete

# 📝 Génération du rapport final
python phoenix.py generer-rapport --output "RAPPORT_INCIDENT_RANSOMWARE_FINAL.md"
```

### 🎯 Types d'Artefacts Supportés

| Format | Support | Fonctionnalités |
|--------|---------|-----------------|
| **`.evtx`** | ✅ Natif | Parsing XML, filtrage Event ID, extraction timestamps |
| **`.csv`** | ✅ Intelligent | Génération code Pandas, contexte d'enquête, validation |
| **`.json`** | ✅ Structuré | Analyse de structure, extraction IoCs |
| **`.log/.txt`** | ✅ Générique | Analyse textuelle, pattern matching |
| **`.xml`** | ✅ Générique | Support du contenu structuré |

## 🗂️ Fichiers d'Exemple

Le dossier `samples/` contient des fichiers d'exemple pour tester Phoenix :
- `auth.log` : Logs d'authentification SSH avec IPs suspectes
- `firewall_logs.csv` : Logs de pare-feu au format CSV
- `report.json` : Rapport d'incident au format JSON

## 🛣️ Fonctionnalités Implémentées v4.0

### ✅ **RÉALISÉ** - Fonctionnalités Principales
- ✅ **Interface CLI professionnelle** avec Typer
- ✅ **Gestion de session persistante** avec JSON
- ✅ **Support EVTX natif** avec filtrage Event ID
- ✅ **Timeline automatique** avec extraction de timestamps
- ✅ **Rapports professionnels** avec résumé exécutif IA
- ✅ **CSV contextuel intelligent** avec IoCs d'enquête
- ✅ **Enrichissement automatique** VirusTotal
- ✅ **Architecture modulaire** extensible

### 🎯 Vision Long Terme
Phoenix v4.0 représente une **plateforme DFIR mature et professionnelle**, prête pour un déploiement en environnement de production et une adoption par la communauté cybersécurité mondiale.

## 🤝 Contribution

Les contributions sont les bienvenues ! Cette version finale offre une base solide pour l'extension :

1. **Fork** le projet
2. **Créez** votre branche de fonctionnalité (`git checkout -b feature/NewAnalyzer`)
3. **Committez** vos changements (`git commit -m 'Add PCAP analyzer'`)
4. **Push** vers la branche (`git push origin feature/NewAnalyzer`)
5. **Ouvrez** une Pull Request

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 🏆 Reconnaissance

**Phoenix v4.0 FINAL** - Créé avec ❤️ pour la communauté DFIR mondiale

*Une plateforme d'investigation hybride IA mature, prête pour la production*

---

<div align="center">

**[⭐ N'oubliez pas de mettre une étoile si ce projet vous aide !](https://github.com/servais1983/phoenix-dfir)**

![Phoenix v4.0](https://img.shields.io/badge/🔥-Phoenix_v4.0_FINAL-orange?style=for-the-badge)
*L'assistant DFIR qui révolutionne l'investigation cybersécurité* 🚀

</div>