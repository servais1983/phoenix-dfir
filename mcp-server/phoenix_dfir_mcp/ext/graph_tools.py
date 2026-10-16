"""Graphe d'entites du cas : construction, pivots, patient zero, rayon d'impact.

Le calcul est dans phoenix_dfir_mcp/graph.py ; graph_build ecrit
<case_dir>/entity_graph.json (contrat JSON version 1). Les outils de requete
recalculent le graphe a partir de l'etat courant (index des preuves + constats)
sans rien ecrire.
"""

import os

from .. import graph, toolkit
from . import _internal

AGENT = ('graph', "Agent Graphe d'entites & pivots")
READONLY = ('graph_neighbors', 'graph_blast_radius', 'graph_patient_zero')
PHASE_TOOLS = {
    'correlation': ('graph_build', 'graph_neighbors', 'graph_patient_zero', 'graph_blast_radius'),
    'contre_analyse': ('graph_neighbors', 'graph_patient_zero', 'graph_blast_radius'),
    'rapport': ('graph_patient_zero', 'graph_blast_radius'),
}

_internal.register(names=(graph.GRAPH_FILE, graph.GRAPH_FILE + '.tmp'))

_CASE = {'case_dir': {'type': 'string', 'description': 'Dossier du cas'}}


def _check(case_dir):
    if not case_dir or not os.path.isdir(case_dir):
        return {'error': f"Dossier introuvable: {case_dir}"}
    return None


@toolkit.tool(
    'graph_build',
    "Construire le graphe d'entites du cas (utilisateurs, hotes, processus pid/ppid, fichiers, IP, "
    "domaines, URL, comptes cloud, cles de registre, services) et leurs relations (authentification, "
    "execution, parente, connexion, resolution, ecriture, creation de service...) a partir de la "
    "super-timeline et des constats. Ecrit entity_graph.json et renvoie le patient zero et le rayon "
    "d'impact.",
    {'type': 'object', 'properties': dict(_CASE), 'required': ['case_dir']},
)
def graph_build(case_dir):
    err = _check(case_dir)
    if err:
        return err
    g = graph.build_and_save(case_dir)
    return {'graph_file': graph.graph_path(case_dir), **graph.summary(g),
            'patient_zero': g['patient_zero'], 'blast_radius': g['blast_radius']}


@toolkit.tool(
    'graph_neighbors',
    "Pivoter sur une entite : voisins dans le graphe jusqu'a `depth` sauts, avec relations, "
    "horodatages et references de preuve. Entite = id (ex: 'host:SRV-01', 'ip:45.137.21.9') ou "
    "libelle.",
    {'type': 'object', 'properties': dict(_CASE, **{
        'entity': {'type': 'string', 'description': "Entite (id 'type:valeur' ou libelle)"},
        'depth': {'type': 'integer', 'description': 'Nombre de sauts (1-4, defaut 1)'},
    }), 'required': ['case_dir', 'entity']},
)
def graph_neighbors(case_dir, entity, depth=1):
    err = _check(case_dir)
    return err or graph.neighbors(graph.build(case_dir), entity, depth)


@toolkit.tool(
    'graph_blast_radius',
    "Rayon d'impact : hotes et comptes atteignables depuis une entite compromise APRES son premier "
    "evenement malveillant, par des relations encore actives ensuite, dans l'ordre chronologique. "
    "Sans seed : depuis le patient zero.",
    {'type': 'object', 'properties': dict(_CASE, **{
        'seed': {'type': 'string', 'description': 'Entite de depart (defaut : patient zero)'},
        'depth': {'type': 'integer', 'description': 'Nombre max de sauts (defaut 6)'},
    }), 'required': ['case_dir']},
)
def graph_blast_radius(case_dir, seed=None, depth=graph.DEFAULT_BLAST_DEPTH):
    err = _check(case_dir)
    return err or graph.blast_radius(graph.build(case_dir), seed, depth)


@toolkit.tool(
    'graph_patient_zero',
    "Patient zero : entite malveillante la plus ancienne (premier evenement cite par un constat "
    "retenu), avec le chemin chronologique et le raisonnement.",
    {'type': 'object', 'properties': dict(_CASE), 'required': ['case_dir']},
)
def graph_patient_zero(case_dir):
    err = _check(case_dir)
    return err or graph.patient_zero(graph.build(case_dir))
