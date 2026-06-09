#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phoenix DFIR - Blueprints de l'API REST.

Chaque module expose un blueprint `bp` ; register_blueprints les attache tous
a l'application.
"""

from routes.health import bp as health_bp
from routes.investigations import bp as investigations_bp
from routes.iocs import bp as iocs_bp
from routes.timeline import bp as timeline_bp
from routes.artifacts import bp as artifacts_bp
from routes.analysis import bp as analysis_bp
from routes.reports import bp as reports_bp
from routes.stats import bp as stats_bp
from routes.stix import bp as stix_bp
from routes.integrations import bp as integrations_bp
from routes.mitre_attack import bp as mitre_bp

ALL_BLUEPRINTS = [
    health_bp,
    investigations_bp,
    iocs_bp,
    timeline_bp,
    artifacts_bp,
    analysis_bp,
    reports_bp,
    stats_bp,
    stix_bp,
    integrations_bp,
    mitre_bp,
]


def register_blueprints(app):
    """Enregistrer tous les blueprints de l'API sur l'application Flask"""
    for blueprint in ALL_BLUEPRINTS:
        app.register_blueprint(blueprint)
