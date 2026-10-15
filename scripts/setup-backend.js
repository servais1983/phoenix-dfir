#!/usr/bin/env node
/**
 * Phoenix DFIR - Backend Setup Script
 * Configure l'environnement Python automatiquement
 */

import { execSync } from 'child_process';
import { existsSync, mkdirSync } from 'fs';
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
const venvPip = isWindows
  ? join(VENV_DIR, 'Scripts', 'pip.exe')
  : join(VENV_DIR, 'bin', 'pip');

console.log('='.repeat(50));
console.log('  Phoenix DFIR - Configuration Backend');
console.log('='.repeat(50));

for (const dir of ['uploads', 'sessions', 'reports']) {
  const dirPath = join(BACKEND_DIR, dir);
  if (!existsSync(dirPath)) {
    mkdirSync(dirPath, { recursive: true });
    console.log(`  Dossier cree: ${dir}/`);
  }
}

if (!existsSync(VENV_DIR)) {
  console.log('\n  Creation de l\'environnement virtuel...');
  try {
    execSync(`${pythonCmd} -m venv "${VENV_DIR}"`, { cwd: BACKEND_DIR, stdio: 'inherit' });
    console.log('  Environnement virtuel cree.');
  } catch {
    console.error('  ERREUR: Python 3 requis. Installez Python 3.9+');
    process.exit(1);
  }
}

console.log('\n  Installation des dependances Python...');
try {
  execSync(`"${venvPip}" install -r requirements.txt`, { cwd: BACKEND_DIR, stdio: 'inherit' });
  console.log('\n  Dependances installees.');
} catch {
  console.error('  ATTENTION: Erreur durant l\'installation des dependances Python.');
}

console.log('\n  Installation des dependances optionnelles (best-effort)...');
try {
  execSync(`"${venvPip}" install -r requirements-optional.txt`, { cwd: BACKEND_DIR, stdio: 'inherit' });
} catch {
  console.log('  Dependances optionnelles ignorees (python-evtx/hexdump non compilable ici).');
}

console.log('\n' + '='.repeat(50));
console.log('  Configuration terminee !');
console.log('  Lancez: npm start');
console.log('='.repeat(50));
