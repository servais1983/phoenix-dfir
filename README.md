# Phoenix DFIR - Interface Graphique Professionnelle

![Phoenix DFIR](https://img.shields.io/badge/🔥-Phoenix_DFIR_GUI-orange?style=for-the-badge)
![React](https://img.shields.io/badge/React-18.2.0-blue?style=for-the-badge&logo=react)
![Flask](https://img.shields.io/badge/Flask-2.3.2-green?style=for-the-badge&logo=flask)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0.0-blue?style=for-the-badge&logo=typescript)

**Interface graphique moderne et professionnelle pour Phoenix DFIR - L'assistant d'investigation forensique alimenté par l'IA**

---

## 🎯 Vue d'ensemble

Cette interface graphique transforme Phoenix DFIR en une plateforme web moderne et intuitive, offrant aux analystes forensiques une expérience utilisateur professionnelle pour leurs investigations de cybersécurité.

### ✨ Fonctionnalités Principales

- **🖥️ Interface Moderne** : Design professionnel sombre adapté aux analystes
- **📊 Dashboard Interactif** : Vue d'ensemble des enquêtes et statistiques en temps réel
- **🔍 Analyseur de Fichiers** : Support multi-format avec glisser-déposer
- **⏰ Timeline Visuelle** : Chronologie interactive des événements
- **🚨 Gestion des IoCs** : Indicateurs de compromission enrichis automatiquement
- **📝 Générateur de Rapports** : Rapports professionnels avec prévisualisation
- **🔄 Temps Réel** : Suivi des analyses longues via WebSockets
- **🌐 API RESTful** : Backend Flask robuste et extensible

## 🏗️ Architecture

### Frontend (React)
- **React 18** avec hooks modernes
- **Tailwind CSS** pour le styling
- **shadcn/ui** pour les composants
- **Lucide Icons** pour l'iconographie
- **Socket.IO** pour le temps réel
- **Axios** pour les requêtes HTTP

### Backend (Flask)
- **Flask** avec extensions (CORS, SocketIO)
- **API RESTful** complète
- **WebSockets** pour les notifications
- **Intégration Phoenix** native
- **Support multi-format** (EVTX, CSV, JSON, LOG)

## 🚀 Installation et Démarrage

### Prérequis
- Node.js 18+ et pnpm
- Python 3.9+
- Git

### 1. Cloner le Projet
```bash
git clone https://github.com/servais1983/phoenix-dfir.git
cd phoenix-dfir/phoenix-dfir-gui
```

### 2. Installation Frontend
```bash
# Installer les dépendances
pnpm install

# Démarrer le serveur de développement
pnpm run dev --host
```
L'interface sera accessible sur `http://localhost:5173`

### 3. Installation Backend
```bash
# Aller dans le dossier backend
cd backend

# Installer les dépendances Python
pip install -r requirements.txt

# Démarrer le serveur Flask
python app.py
```
L'API sera accessible sur `http://localhost:5000`

### 4. Configuration (Optionnel)
Pour activer toutes les fonctionnalités IA, éditez `backend/src/phoenix_service.py` :
```python
API_KEY_GOOGLE = "votre_cle_google_ai"
API_KEY_VT = "votre_cle_virustotal"
```

## 📖 Guide d'Utilisation

### 1. Créer une Nouvelle Enquête
1. Cliquez sur "Nouvelle Enquête" dans l'onglet Enquêtes
2. Donnez un nom à votre investigation
3. L'enquête est automatiquement sauvegardée

### 2. Analyser des Fichiers
1. Allez dans l'onglet "Analyseur"
2. Glissez-déposez vos fichiers (EVTX, CSV, JSON, LOG, TXT)
3. Décrivez votre question d'analyse
4. Configurez les paramètres si nécessaire
5. Lancez l'analyse et suivez le progrès en temps réel

### 3. Visualiser la Timeline
1. L'onglet "Timeline" affiche automatiquement les événements
2. Filtrez par type ou période
3. Exportez les données si nécessaire

### 4. Gérer les IoCs
1. L'onglet "IoCs" liste tous les indicateurs détectés
2. Chaque IoC est automatiquement enrichi via VirusTotal
3. Visualisez les scores de réputation et sources

### 5. Générer des Rapports
1. Dans l'onglet "Rapports", configurez votre rapport
2. Choisissez le template et format
3. Prévisualisez en temps réel
4. Générez et téléchargez le rapport final

## 🔧 API Endpoints

### Enquêtes
- `GET /api/investigations` - Liste des enquêtes
- `POST /api/investigations` - Créer une enquête
- `GET /api/investigations/{id}` - Détails d'une enquête

### Analyse
- `POST /api/upload` - Upload de fichier
- `POST /api/analyze` - Lancer une analyse
- `GET /api/analysis/{id}/status` - Statut d'analyse

### Rapports
- `POST /api/reports/generate` - Générer un rapport
- `GET /api/reports/{id}/download` - Télécharger un rapport

### Système
- `GET /api/health` - Health check

## 🔌 WebSocket Events

### Côté Client
- `join_investigation` - Rejoindre une enquête
- `analysis_progress` - Suivi d'analyse en temps réel
- `notification` - Notifications système

## 📁 Structure du Projet

```
phoenix-dfir-gui/
├── src/                     # Code source React
│   ├── components/          # Composants React
│   │   └── ui/             # Composants shadcn/ui
│   ├── services/           # Services API et WebSocket
│   ├── assets/             # Assets statiques
│   ├── App.jsx             # Composant principal
│   └── main.jsx            # Point d'entrée
├── backend/                # Backend Flask
│   ├── src/                # Services Python
│   ├── uploads/            # Fichiers uploadés
│   ├── sessions/           # Sessions d'enquête
│   ├── reports/            # Rapports générés
│   └── app.py              # Application Flask
├── public/                 # Fichiers publics
└── package.json            # Dépendances Node.js
```

## 🎨 Captures d'Écran

### Dashboard Principal
Interface moderne avec statistiques en temps réel et vue d'ensemble des enquêtes actives.

### Analyseur de Fichiers
Zone de glisser-déposer intuitive avec support multi-format et configuration avancée.

### Timeline Interactive
Visualisation chronologique des événements avec filtrage et navigation temporelle.

### Gestion des IoCs
Tableau interactif des indicateurs avec enrichissement automatique VirusTotal.

### Générateur de Rapports
Interface WYSIWYG avec prévisualisation en temps réel et templates professionnels.

## 🔐 Sécurité

- **CORS** configuré pour les origines autorisées
- **Validation** des fichiers uploadés
- **Sanitisation** des noms de fichiers
- **Timeouts** sur les requêtes API
- **Gestion d'erreurs** robuste

## 🚀 Déploiement

### Développement
```bash
# Frontend
pnpm run dev --host

# Backend
python backend/app.py
```

### Production
```bash
# Build frontend
pnpm run build

# Servir avec un serveur web (nginx, apache)
# Backend avec Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 backend.app:app
```

## 🤝 Contribution

1. Fork le projet
2. Créez votre branche (`git checkout -b feature/AmazingFeature`)
3. Committez vos changements (`git commit -m 'Add AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une Pull Request

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](../LICENSE) pour plus de détails.

## 🙏 Remerciements

- **Phoenix DFIR** pour le moteur d'analyse forensique
- **shadcn/ui** pour les composants UI
- **Tailwind CSS** pour le framework CSS
- **React** pour le framework frontend
- **Flask** pour le framework backend

---

<div align="center">

**[⭐ N'oubliez pas de mettre une étoile si ce projet vous aide !](https://github.com/servais1983/phoenix-dfir)**

![Phoenix DFIR GUI](https://img.shields.io/badge/🔥-Phoenix_DFIR_GUI-orange?style=for-the-badge)
*L'interface graphique qui révolutionne l'investigation forensique* 🚀

</div>
