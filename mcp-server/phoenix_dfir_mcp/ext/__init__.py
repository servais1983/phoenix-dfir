"""Extensions d'outils DFIR.

Chaque module de ce paquet (decouvert automatiquement, ordre alphabetique ;
les modules prefixes par '_' sont ignores) enregistre ses outils avec
`toolkit.tool(...)` et declare, au niveau du module, des constantes
optionnelles que toolkit et phases fusionnent au chargement :

    AGENT = ('cle', 'Libelle de l agent')     agent de la console qui opere ses outils
    READONLY = ('outil', ...)                  outils sans effet de bord (verification)
    INDEXED = ('outil', ...)                   sorties indexees dans la super-timeline
    KNOWN_TYPES = {'.ext': 'Type d artefact'}  types reconnus par list_artifacts
    PHASE_TOOLS = {'extraction': (...), ...}   outils autorises par phase
    PHASE_HINTS = {'extraction': '...'}        consignes ajoutees a la phase
    def applicable(path) -> list | None        groupes d outils pour l audit de couverture
                                               (None : artefact non concerne)

Les modules sont independants : un module qui echoue a l'import est ignore
et signale, sans casser les autres outils.
"""

import pkgutil

EXTENSIONS = tuple(sorted(m.name for m in pkgutil.iter_modules(__path__) if not m.name.startswith('_')))
