# Guide d'Installation - Phoenix DFIR Interface Graphique

## 🎯 Installation Rapide (Recommandée)

### Prérequis
- **Node.js 18+** et **pnpm** (ou npm)
- **Python 3.9+** 
- **Git**

### Étapes d'Installation

#### 1. Cloner le Repository
```bash
git clone https://github.com/servais1983/phoenix-dfir.git
cd phoenix-dfir/phoenix-dfir-gui
```

#### 2. Installation Frontend
```bash
# Installer les dépendances
pnpm install

# Démarrer le serveur de développement
pnpm run dev --host
```
✅ **Frontend accessible sur:** `http://localhost:5173`

#### 3. Installation Backend (Terminal séparé)
```bash
# Aller dans le dossier backend
cd backend

# Créer un environnement virtuel (recommandé)
python -m venv venv

# Activer l'environnement virtuel
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt
# Optionnel (parsing EVTX, providers IA) - peut échouer sans bloquer :
pip install -r requirements-optional.txt

# Démarrer le serveur Flask
python app.py
```
✅ **Backend accessible sur:** `http://localhost:5000`

#### 4. Vérification
- Ouvrez `http://localhost:5173` dans votre navigateur
- L'interface Phoenix DFIR devrait s'afficher
- Vérifiez l'API : `http://localhost:5000/api/health`

## 🔧 Configuration Avancée

### Analyse IA avec GitHub Copilot

L'IA de Phoenix repose **exclusivement sur GitHub Copilot**, via l'[API GitHub Models](https://docs.github.com/en/github-models). Aucune dépendance supplémentaire n'est requise (seul `requests` est utilisé) — installez simplement `typer` et `pandas` pour activer le moteur d'analyse (`pip install -r backend/requirements-optional.txt`).

1. **Créer un jeton GitHub**
   - Allez sur [github.com/settings/tokens](https://github.com/settings/tokens)
   - Créez un *fine-grained personal access token* avec la permission **Models: read**
   - L'accès à GitHub Models est inclus avec les comptes GitHub et les abonnements Copilot
2. **Configurer les variables d'environnement**

```bash
# Jeton GitHub (obligatoire pour l'analyse IA)
export GITHUB_TOKEN="github_pat_..."        # ou PHOENIX_GITHUB_TOKEN

# Optionnel : choisir le modèle (défaut : openai/gpt-4o-mini)
# Catalogue complet : https://github.com/marketplace/models
export PHOENIX_GITHUB_MODEL="openai/gpt-4o"
```

3. **Redémarrer le backend** — les analyses d'artefacts, l'extraction d'IoCs et les résumés exécutifs utilisent alors GitHub Copilot.

Sans jeton GitHub, l'analyse IA est indisponible mais la plateforme reste fonctionnelle avec ses parsers natifs (mode standalone).

### Clé VirusTotal (Optionnel)

Pour l'enrichissement automatique des IoCs :

```bash
export API_KEY_VT="votre_cle_virustotal"
```

**Obtenir la clé (Gratuit)**
1. Créez un compte sur [VirusTotal](https://virustotal.com)
2. Allez dans votre profil → API Key
3. Copiez la clé dans la variable d'environnement `API_KEY_VT`

## 🐳 Installation avec Docker (Alternative)

### Dockerfile Frontend
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host"]
```

### Dockerfile Backend
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install -r requirements.txt
COPY backend/ .
EXPOSE 5000
CMD ["python", "app.py"]
```

### Docker Compose
```yaml
version: '3.8'
services:
  frontend:
    build: .
    ports:
      - "5173:5173"
    depends_on:
      - backend
  
  backend:
    build: 
      context: .
      dockerfile: Dockerfile.backend
    ports:
      - "5000:5000"
    volumes:
      - ./backend/uploads:/app/uploads
      - ./backend/sessions:/app/sessions
      - ./backend/reports:/app/reports
```

## 🔧 Dépannage

### Problèmes Courants

#### 1. Erreur "Module not found"
```bash
# Réinstaller les dépendances
cd phoenix-dfir-gui
rm -rf node_modules package-lock.json
pnpm install
```

#### 2. Erreur de connexion API
- Vérifiez que le backend tourne sur le port 5000
- Testez l'API : `curl http://localhost:5000/api/health`
- Vérifiez les logs du serveur Flask

#### 3. Problèmes de CORS
- Le backend est configuré pour accepter `localhost:5173`
- Si vous changez le port, mettez à jour `backend/app.py`

#### 4. Erreur Python "Module not found"
```bash
# Vérifier l'environnement virtuel
which python
pip list

# Réinstaller les dépendances
pip install -r requirements.txt
```

### Logs et Debug

#### Frontend (React)
- Ouvrez les outils développeur (F12)
- Consultez la console pour les erreurs JavaScript
- Onglet Network pour les requêtes API

#### Backend (Flask)
- Les logs s'affichent dans le terminal
- Mode debug activé par défaut en développement
- Fichiers de logs dans `backend/logs/` (si configuré)

## 🚀 Déploiement en Production

### Frontend (Build de Production)
```bash
# Construire l'application
pnpm run build

# Servir avec nginx ou apache
# Exemple nginx:
server {
    listen 80;
    server_name votre-domaine.com;
    root /path/to/dist;
    
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    location /api {
        proxy_pass http://localhost:5000;
    }
}
```

### Backend (Production)
```bash
# Installer Gunicorn
pip install gunicorn

# Démarrer avec Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Ou avec systemd (Linux)
sudo systemctl enable phoenix-dfir-backend
sudo systemctl start phoenix-dfir-backend
```

### Variables d'Environnement
```bash
# Créer un fichier .env
FLASK_ENV=production
SECRET_KEY=votre-clé-secrète-très-longue
GITHUB_TOKEN=votre-jeton-github-models    # IA GitHub Copilot (permission Models: read)
PHOENIX_GITHUB_MODEL=openai/gpt-4o-mini   # modèle GitHub Models (optionnel)
API_KEY_VT=votre-clé-virustotal           # enrichissement IoCs (optionnel)
```

## 📋 Checklist d'Installation

- [ ] Node.js 18+ installé
- [ ] Python 3.9+ installé
- [ ] Repository cloné
- [ ] Dépendances frontend installées (`pnpm install`)
- [ ] Dépendances backend installées (`pip install -r requirements.txt`)
- [ ] Frontend démarré (`pnpm run dev --host`)
- [ ] Backend démarré (`python app.py`)
- [ ] Interface accessible sur `http://localhost:5173`
- [ ] API accessible sur `http://localhost:5000/api/health`
- [ ] Jeton GitHub configuré pour l'IA Copilot (`GITHUB_TOKEN`, optionnel)
- [ ] Clé VirusTotal configurée (optionnel)

## 🆘 Support

Si vous rencontrez des problèmes :

1. **Vérifiez les prérequis** et versions
2. **Consultez les logs** frontend et backend
3. **Testez l'API** avec curl ou Postman
4. **Ouvrez une issue** sur GitHub avec :
   - Votre système d'exploitation
   - Versions de Node.js et Python
   - Messages d'erreur complets
   - Étapes pour reproduire le problème

---

**🔥 Phoenix DFIR Interface Graphique - Installation réussie !** 🚀
