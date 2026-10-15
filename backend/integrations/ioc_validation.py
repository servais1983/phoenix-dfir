"""
Phoenix DFIR - Validation et encodage des IoCs avant appel d'API externes.

Les valeurs d'IoC proviennent d'artefacts controles par l'attaquant (ou d'un
LLM pilote par ces artefacts). Interpolees telles quelles dans le CHEMIN d'une
URL d'API portant la cle de l'organisation, une valeur comme
'8.8.8.8/../../users/me' ou '1.2.3.4?x=' detourne la requete vers un autre
endpoint. Chaque valeur est donc validee strictement selon son type, puis
encodee (urllib.parse.quote(..., safe='')) avant interpolation.
"""

import base64
import ipaddress
import re
from urllib.parse import quote, urlsplit

MAX_IOC_LENGTH = 2048

_HASH_LENGTHS = {'hash_md5': (32,), 'hash_sha1': (40,), 'hash_sha256': (64,),
                 'hash': (32, 40, 64)}
_HEX = re.compile(r'^[0-9a-fA-F]+$')
_DOMAIN = re.compile(
    r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+'
    r'(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})$')
_EMAIL = re.compile(r'^[A-Za-z0-9._%+-]{1,64}@(?P<domain>[^@\s]+)$')
_CVE = re.compile(r'^CVE-\d{4}-\d{4,7}$', re.IGNORECASE)


class InvalidIoC(ValueError):
    """Valeur d'IoC invalide pour le type annonce."""


def _fail(ioc_type, reason):
    raise InvalidIoC(f"IoC {ioc_type} invalide : {reason}")


def validate_ioc(ioc_type, value):
    """Retourner la valeur normalisee, ou lever InvalidIoC."""
    if not isinstance(value, str):
        _fail(ioc_type, 'valeur texte attendue')
    value = value.strip()
    if not value or len(value) > MAX_IOC_LENGTH:
        _fail(ioc_type, 'valeur vide ou trop longue')
    if any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7f for c in value):
        _fail(ioc_type, 'caracteres d\'espacement ou de controle interdits')

    if ioc_type in ('ip', 'ipv4', 'ipv6'):
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            _fail(ioc_type, f"'{value[:80]}' n'est pas une adresse IP")
        if ioc_type == 'ipv4' and addr.version != 4:
            _fail(ioc_type, 'IPv4 attendue')
        if ioc_type == 'ipv6' and addr.version != 6:
            _fail(ioc_type, 'IPv6 attendue')
        return str(addr)
    if ioc_type in _HASH_LENGTHS:
        if not _HEX.match(value) or len(value) not in _HASH_LENGTHS[ioc_type]:
            _fail(ioc_type, f'empreinte hexadecimale de {"/".join(map(str, _HASH_LENGTHS[ioc_type]))} '
                            'caracteres attendue')
        return value.lower()
    if ioc_type in ('domain', 'hostname'):
        candidate = value.rstrip('.')
        if not _DOMAIN.match(candidate):
            _fail(ioc_type, f"'{value[:80]}' n'est pas un nom de domaine valide")
        return candidate.lower()
    if ioc_type == 'url':
        parts = urlsplit(value)
        if parts.scheme.lower() not in ('http', 'https', 'ftp') or not parts.netloc:
            _fail(ioc_type, 'URL http(s)/ftp absolue attendue')
        return value
    if ioc_type == 'email':
        m = _EMAIL.match(value)
        if not m or not _DOMAIN.match(m.group('domain')):
            _fail(ioc_type, 'adresse email invalide')
        return value
    if ioc_type == 'cve':
        if not _CVE.match(value):
            _fail(ioc_type, 'identifiant CVE-AAAA-NNNN attendu')
        return value.upper()
    _fail(ioc_type, 'type non supporte')
    return None  # pragma: no cover


def path_segment(value):
    """Encoder une valeur pour un segment de chemin d'URL (aucun '/', '?', '#'...)."""
    return quote(str(value), safe='')


def vt_url_id(url):
    """Identifiant VirusTotal d'une URL : base64url sans remplissage."""
    return base64.urlsafe_b64encode(url.encode('utf-8')).decode('ascii').rstrip('=')


def safe_ioc_segment(ioc_type, value):
    """Valider puis encoder une valeur d'IoC pour un chemin d'URL."""
    return path_segment(validate_ioc(ioc_type, value))


def invalid_response(error):
    """Reponse standard des connecteurs pour un IoC rejete."""
    return {'success': False, 'error': str(error), 'message': str(error)}
