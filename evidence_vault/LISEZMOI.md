# Coffre de preuves Phoenix DFIR

Deposez ici les evidences originales : journaux `.evtx`, `$MFT`, ruches de
registre, dumps memoire (`.raw`, `.mem`, `.vmem`, `.dmp`, `.lime`).

- En Docker, ce dossier est monte **en lecture seule** sur `/mnt/evidence` :
  Phoenix ne peut ni modifier ni supprimer les originaux.
- Depuis la **Console SOC**, selectionnez les fichiers et rattachez-les a une
  enquete : les empreintes MD5/SHA1/SHA256 sont calculees et l'acquisition est
  scellee dans la chaine de preuve (Chain of Custody).
- Le contenu de ce dossier est ignore par Git.

Sous Windows, excluez ce dossier de l'analyse temps reel de Defender
(voir `docs/WINDOWS_DOCKER.md`), sinon des artefacts malveillants risquent
d'etre mis en quarantaine et l'investigation brisee.
