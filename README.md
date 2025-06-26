
![image](phoenix.png)

# 🔥 Phoenix - Assistant d'Analyse DFIR par IA

<div align="center">

![Phoenix Logo](https://img.shields.io/badge/🔥-Phoenix-orange?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.1-brightgreen?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**🚀 Un assistant interactif hybride pour l'investigation numérique et la réponse aux incidents**

[🎯 Fonctionnalités](#-fonctionnalités-clés) • [⚡ Installation](#-installation-rapide) • [📖 Guide d'utilisation](#-guide-dutilisation) • [🔧 Configuration](#-configuration)

</div>

---

## 🎯 Vue d'ensemble

Phoenix est un assistant interactif en ligne de commande, spécialisé dans l'aide à l'investigation numérique et la réponse aux incidents (DFIR). Il est conçu pour être un **partenaire intelligent** pour l'analyste, capable de traiter, d'analyser et de corréler des informations provenant de divers artefacts forensiques.

### 🧠 Philosophie IA Hybride

Le projet repose sur une **approche d'IA hybride** innovante, combinant :
- 🏠 **Rapidité et confidentialité** d'un modèle de langage local (via Ollama) pour les tâches sensibles
- ☁️ **Puissance et capacités avancées** d'un modèle de pointe via API pour les tâches complexes

## ✨ Fonctionnalités Clés

### 🔄 Moteur IA Hybride
- Utilise dynamiquement un modèle local (privé et rapide) et un modèle distant (puissant)
- Sélection automatique du meilleur modèle selon la tâche

### 🔍 Analyseur Polymorphe
- Détection automatique du type de fichier (`.csv`, `.json`, `.log`, `.txt`...)
- Application de la méthode d'analyse la plus pertinente pour chaque format

### 📂 Gestion d'Enquête
- Maintient un **"dossier d'enquête"** actif pour chaque session
- Conservation du contexte et des découvertes au fil du temps

### 🔗 Corrélation Autonome
- Extraction automatique des **Indicateurs de Compromission (IoCs)** 
- Ajout intelligent au dossier d'enquête pour relier les points entre artefacts

### 💻 Interface Ligne de Commande
- Interface simple et directe pour gérer les enquêtes
- Commandes intuitives pour lancer des analyses et consulter les résultats

### 🧩 Architecture Modulaire
- Conçu pour être facilement extensible
- Prêt pour de nouveaux analyseurs (ex: `.evtx`, ruches de registre...)

## 🏗️ Architecture du Système

```
Phoenix v2.1
├── 🎯 Boucle Principale (main)
│   └── Cœur interactif qui écoute les commandes
├── 🔀 Aiguilleur d'Analyse (analyse_fichier)
│   └── Identification du type de fichier et routage
├── ⚙️ Gestionnaires Spécialisés
│   ├── handle_csv (Pandas + IA)
│   ├── handle_json (Structure + IA)
│   └── handle_generic_text (IA locale)
├── 🧠 Mémoire d'Enquête (dossier_enquete)
│   └── État global de l'investigation
└── 🔍 Moteur d'Extraction
    └── IA "méta" pour extraire des informations structurées
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

### 🔑 Configuration de la Clé API
1. Obtenez une clé API gratuite depuis [Google AI Studio](https://aistudio.google.com)
2. Ouvrez le fichier `phoenix.py`
3. Remplacez `"VOTRE_API_KEY_ICI"` par votre clé API

```python
API_KEY_GOOGLE = "votre-clé-api-ici"
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
| `resume_enquete` | 📋 Affiche le résumé complet du cas | `resume_enquete` |
| `ajoute_ioc <type> <valeur>` | ➕ Ajoute manuellement un IoC | `ajoute_ioc ip 142.250.70.14` |
| `analyse <fichier> "<question>"` | 🔍 Lance une analyse sur un fichier | `analyse auth.log "échecs de connexion suspects ?"` |
| `quitter` | 🚪 Arrête Phoenix | `quitter` |

### 🎯 Types d'IoCs Supportés
- **`ips`** : Adresses IP suspectes
- **`hashes`** : Hachages de fichiers
- **`domaines`** : Noms de domaines suspects

## 🔥 Exemple de Scénario d'Enquête

```bash
# 🚀 Lancement de Phoenix
python phoenix.py

# 🆕 Nouvelle enquête
Vous: nouvelle_enquete Intrusion-SSH

# 🔍 Première analyse
Vous: analyse auth.log "cherche les IP suspectes liées à des échecs de connexion"
# ... Phoenix retourne son analyse et sauvegarde les IoCs ...

# 📋 État de l'enquête
Vous: resume_enquete
# ... Phoenix affiche le dossier avec l'IP suspecte 103.207.39.45 ...

# 🔗 Corrélation avec un autre artefact
Vous: analyse firewall_logs.csv "montre-moi toute l'activité pour l'IP 103.207.39.45"
# ... Phoenix utilise Pandas pour filtrer le CSV et retourne les logs pertinents ...

# 📊 Dossier consolidé
Vous: resume_enquete
# ... Le dossier contient maintenant l'analyse de deux artefacts et les IoCs consolidés ...

# 🚪 Fin de session
Vous: quitter
```

## 🗂️ Fichiers d'Exemple

Le dossier `samples/` contient des fichiers d'exemple pour tester Phoenix :
- `auth.log` : Logs d'authentification SSH
- `firewall_logs.csv` : Logs de pare-feu au format CSV
- `report.json` : Rapport d'incident au format JSON

## 🛣️ Feuille de Route

### 🔜 Prochaines Fonctionnalités
- **[Analyseurs]** Support des formats binaires (`.evtx`, Ruches de Registre, Prefetch)
- **[Intelligence]** Corrélation avancée utilisant les IoCs comme contexte
- **[Reporting]** Export automatique en Markdown avec `generer_rapport`
- **[Enrichissement]** Intégration d'API de Threat Intelligence (VirusTotal, etc.)

### 🎯 Vision Long Terme
Faire de Phoenix un outil **incontournable** pour la communauté DFIR mondiale.

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

Créé avec ❤️ pour la communauté DFIR

---

<div align="center">

**[⭐ N'oubliez pas de mettre une étoile si ce projet vous aide !](https://github.com/servais1983/phoenix-dfir)**

</div>
