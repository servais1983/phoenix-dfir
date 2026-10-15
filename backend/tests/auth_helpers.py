"""Helpers de test : creation des comptes avec le modele d'inscription securise.

- bootstrap_admin : premiere inscription avec le jeton d'installation (admin) ;
- create_user : creation par l'admin (POST /api/auth/users) puis connexion.
"""


def bootstrap_admin(client, username, password, display_name=None):
    """Creer l'admin initial sur une base vide et renvoyer la reponse JSON."""
    import auth
    resp = client.post('/api/auth/register', json={
        'username': username,
        'password': password,
        'display_name': display_name or username,
        'setup_token': auth.get_setup_token(),
    })
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()


def create_user(client, admin_token, username, password, role='analyst', display_name=None):
    """Creer un utilisateur (admin) puis le connecter ; renvoie la reponse de login."""
    resp = client.post('/api/auth/users', json={
        'username': username, 'password': password, 'role': role,
        'display_name': display_name or username,
    }, headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 201, resp.get_json()
    login = client.post('/api/auth/login', json={'username': username, 'password': password})
    assert login.status_code == 200, login.get_json()
    return login.get_json()


def add_member(client, token, investigation_id, username):
    resp = client.post(f'/api/investigations/{investigation_id}/members',
                       json={'username': username},
                       headers={'Authorization': f'Bearer {token}'})
    assert resp.status_code in (200, 201), resp.get_json()
    return resp.get_json()
