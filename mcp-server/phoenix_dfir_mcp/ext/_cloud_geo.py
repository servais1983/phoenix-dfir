"""Geolocalisation hors ligne pour la detection de voyage impossible.

Aucune requete reseau : la position vient des champs de localisation du
journal lui-meme (coordonnees Entra ID, ville / pays). A defaut de
coordonnees, la position approximative du pays (capitale) est prise dans la
petite table ci-dessous ; sans pays connu, la connexion est ignoree et
signalee ('no geo'). Aucune table IP -> pays n'est embarquee : deviner un
pays a partir d'une IP sans base a jour produirait de faux positifs.
"""

import math

# ISO 3166-1 alpha-2 -> (latitude, longitude) de la capitale (approximation du pays)
COUNTRY_POS = {
    'AE': (24.45, 54.38), 'AR': (-34.60, -58.38), 'AT': (48.21, 16.37), 'AU': (-35.28, 149.13),
    'BD': (23.81, 90.41), 'BE': (50.85, 4.35), 'BG': (42.70, 23.32), 'BR': (-15.79, -47.88),
    'BY': (53.90, 27.57), 'CA': (45.42, -75.70), 'CH': (46.95, 7.45), 'CL': (-33.45, -70.67),
    'CN': (39.90, 116.40), 'CO': (4.71, -74.07), 'CZ': (50.08, 14.44), 'DE': (52.52, 13.40),
    'DK': (55.68, 12.57), 'DZ': (36.75, 3.06), 'EE': (59.44, 24.75), 'EG': (30.04, 31.24),
    'ES': (40.42, -3.70), 'FI': (60.17, 24.94), 'FR': (48.86, 2.35), 'GB': (51.51, -0.13),
    'GR': (37.98, 23.73), 'HK': (22.32, 114.17), 'HR': (45.81, 15.98), 'HU': (47.50, 19.04),
    'ID': (-6.21, 106.85), 'IE': (53.35, -6.26), 'IL': (31.77, 35.21), 'IN': (28.61, 77.21),
    'IR': (35.69, 51.39), 'IS': (64.15, -21.94), 'IT': (41.90, 12.50), 'JP': (35.68, 139.69),
    'KE': (-1.29, 36.82), 'KP': (39.04, 125.76), 'KR': (37.57, 126.98), 'KZ': (51.17, 71.45),
    'LT': (54.69, 25.28), 'LU': (49.61, 6.13), 'LV': (56.95, 24.11), 'MA': (34.02, -6.84),
    'MD': (47.01, 28.86), 'MX': (19.43, -99.13), 'MY': (3.14, 101.69), 'NG': (9.08, 7.40),
    'NL': (52.37, 4.90), 'NO': (59.91, 10.75), 'NZ': (-41.29, 174.78), 'PE': (-12.05, -77.04),
    'PH': (14.60, 120.98), 'PK': (33.68, 73.05), 'PL': (52.23, 21.01), 'PT': (38.72, -9.14),
    'RO': (44.43, 26.10), 'RS': (44.79, 20.45), 'RU': (55.76, 37.62), 'SA': (24.71, 46.68),
    'SE': (59.33, 18.07), 'SG': (1.35, 103.82), 'SK': (48.15, 17.11), 'SN': (14.72, -17.47),
    'TH': (13.76, 100.50), 'TN': (36.81, 10.18), 'TR': (39.93, 32.86), 'TW': (25.03, 121.57),
    'UA': (50.45, 30.52), 'US': (38.90, -77.04), 'VE': (10.48, -66.90), 'VN': (21.03, 105.85),
    'ZA': (-25.75, 28.19),
}

# Noms usuels (journaux en clair) -> code pays
COUNTRY_NAMES = {
    'france': 'FR', 'united states': 'US', 'usa': 'US', 'united kingdom': 'GB', 'germany': 'DE',
    'netherlands': 'NL', 'belgium': 'BE', 'switzerland': 'CH', 'spain': 'ES', 'italy': 'IT',
    'russia': 'RU', 'china': 'CN', 'nigeria': 'NG', 'brazil': 'BR', 'india': 'IN', 'japan': 'JP',
    'canada': 'CA', 'australia': 'AU', 'singapore': 'SG', 'ukraine': 'UA', 'romania': 'RO',
    'vietnam': 'VN', 'turkey': 'TR', 'iran': 'IR', 'luxembourg': 'LU', 'ireland': 'IE',
}


def country_code(value):
    """Code pays ISO2 depuis un code ou un nom, sinon None."""
    text = str(value or '').strip()
    if len(text) == 2 and text.upper() in COUNTRY_POS:
        return text.upper()
    return COUNTRY_NAMES.get(text.lower())


def position(lat=None, lon=None, country=None):
    """(lat, lon, precision) : 'coords' si le journal fournit des coordonnees,
    'country' si seule la position du pays est connue, sinon None."""
    try:
        if lat not in (None, '') and lon not in (None, ''):
            la, lo = float(lat), float(lon)
            if -90 <= la <= 90 and -180 <= lo <= 180 and (la, lo) != (0.0, 0.0):
                return la, lo, 'coords'
    except (TypeError, ValueError):
        pass
    code = country_code(country)
    if code:
        la, lo = COUNTRY_POS[code]
        return la, lo, 'country'
    return None


def distance_km(a, b):
    """Distance orthodromique (haversine) entre deux positions (lat, lon)."""
    lat1, lon1, lat2, lon2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = (math.sin((lat2 - lat1) / 2) ** 2
         + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2)
    return 2 * 6371.0 * math.asin(min(1.0, math.sqrt(h)))
