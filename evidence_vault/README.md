# Phoenix DFIR evidence vault

Place original evidence here: `.evtx` logs, `$MFT`, registry hives and memory
dumps (`.raw`, `.mem`, `.vmem`, `.dmp`, `.lime`).

- In Docker, this folder is mounted **read-only** at `/mnt/evidence`:
  Phoenix can neither modify nor delete the originals.
- From the **DFIR investigator console**, select the files and attach them to an
  investigation: MD5/SHA1/SHA256 hashes are computed and the acquisition is
  sealed in the chain of custody.
- The contents of this folder are ignored by Git.

On Windows, exclude this folder from Defender real-time scanning
(see `docs/WINDOWS_DOCKER.md`). Otherwise malicious artifacts may be
quarantined and the investigation compromised.
