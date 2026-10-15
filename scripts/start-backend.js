#!/usr/bin/env node
/**
 * Phoenix DFIR - Backend Startup Script
 * Demarre le serveur Flask automatiquement
 */

import { spawn, execSync } from 'child_process';
import { existsSync } from 'fs';
import { resolve, join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const ROOT = resolve(__dirname, '..');
const BACKEND_DIR = join(ROOT, 'backend');
const VENV_DIR = join(BACKEND_DIR, 'venv');

const isWindows = process.platform === 'win32';
const pythonCmd = isWindows ? 'python' : 'python3';
const venvPython = isWindows
  ? join(VENV_DIR, 'Scripts', 'python.exe')
  : join(VENV_DIR, 'bin', 'python');
const venvPip = isWindows
  ? join(VENV_DIR, 'Scripts', 'pip.exe')
  : join(VENV_DIR, 'bin', 'pip');

function log(msg) {
  const timestamp = new Date().toLocaleTimeString();
  console.log(`[${timestamp}] [BACKEND] ${msg}`);
}

function setupVenv() {
  if (!existsSync(venvPython)) {
    log('Creation de l\'environnement virtuel Python...');
    try {
      execSync(`${pythonCmd} -m venv "${VENV_DIR}"`, { cwd: BACKEND_DIR, stdio: 'inherit' });
    } catch {
      log('ERREUR: Python 3 est requis. Installez Python 3.9+ et reessayez.');
      process.exit(1);
    }
  }

  log('Verification des dependances Python...');
  try {
    execSync(`"${venvPip}" install -q -r requirements.txt`, {
      cwd: BACKEND_DIR,
      stdio: 'pipe'
    });
  } catch (e) {
    log(`ATTENTION: Certaines dependances n'ont pas pu etre installees: ${e.message}`);
  }

  // Dependances optionnelles (python-evtx, providers IA) : best-effort
  try {
    execSync(`"${venvPip}" install -q -r requirements-optional.txt`, {
      cwd: BACKEND_DIR,
      stdio: 'pipe'
    });
  } catch {
    log('Dependances optionnelles ignorees (python-evtx/hexdump non compilable ici)');
  }
}

function startBackend() {
  log('Demarrage du serveur Flask sur http://localhost:5000');

  const child = spawn(venvPython, ['app.py'], {
    cwd: BACKEND_DIR,
    stdio: 'inherit',
    env: {
      ...process.env,
      FLASK_ENV: 'development',
      PYTHONUNBUFFERED: '1'
    }
  });

  child.on('error', (err) => {
    log(`Erreur de demarrage: ${err.message}`);
    process.exit(1);
  });

  child.on('exit', (code) => {
    if (code !== 0 && code !== null) {
      log(`Le serveur s'est arrete avec le code: ${code}`);
    }
  });

  process.on('SIGINT', () => {
    child.kill('SIGINT');
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    child.kill('SIGTERM');
    process.exit(0);
  });
}

setupVenv();
startBackend();
