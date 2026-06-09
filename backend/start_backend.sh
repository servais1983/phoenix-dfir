#!/bin/bash

# Script de démarrage pour le backend Phoenix DFIR

echo "🔥 Phoenix DFIR - Démarrage du Backend"
echo "====================================="

# Vérifier si Python est installé
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 n'est pas installé"
    exit 1
fi

# Créer un environnement virtuel s'il n'existe pas
if [ ! -d "venv" ]; then
    echo "📦 Création de l'environnement virtuel..."
    python3 -m venv venv
fi

# Activer l'environnement virtuel
echo "🔧 Activation de l'environnement virtuel..."
source venv/bin/activate

# Installer les dépendances
echo "📥 Installation des dépendances..."
pip install -r requirements.txt
pip install -r requirements-optional.txt || echo "⚠️  Dépendances optionnelles ignorées (python-evtx/hexdump)"

# Créer les dossiers nécessaires
echo "📁 Création des dossiers..."
mkdir -p uploads sessions reports logs

# Démarrer l'application
echo "🚀 Démarrage du serveur Flask..."
echo "Backend disponible sur: http://localhost:5000"
echo "API Health Check: http://localhost:5000/api/health"
echo "====================================="

python app.py
