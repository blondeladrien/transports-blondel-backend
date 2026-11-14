import os
from datetime import date, datetime
from zoneinfo import ZoneInfo
from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_connection, init_db, seed_admin
from auth import generer_token, authentification_requise, verifier_token, serializer

FUSEAU_FR = ZoneInfo('Europe/Paris')


def aujourdhui_fr():
    """Date du jour en heure FRANÇAISE (et non UTC, le fuseau par défaut du serveur Render) —
    indispensable pour que "minuit" corresponde bien à minuit vécu par les chauffeurs, pas à
    minuit UTC qui tombe plusieurs heures plus tôt/tard selon la saison."""
    return datetime.now(FUSEAU_FR).date().isoformat()

app = Flask(__name__)


@app.after_request
def ajouter_headers_cors(response):
    """Autorise les appels depuis les apps web/mobile (fichiers HTML séparés), sans dépendance externe.
    Flask gère automatiquement les requêtes OPTIONS (pré-vérification du navigateur) pour chaque route ;
    ce hook ajoute simplement les bons en-têtes à TOUTES les réponses, y compris ces réponses automatiques."""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PATCH, PUT, DELETE, OPTIONS'
    return response


# ============================================================
# AUTHENTIFICATION
# ============================================================

@app.route('/api/auth/login', methods=['POST'])
def login():
    donnees = request.get_json(force=True) or {}
    identifiant = donnees.get('identifiant', '').strip()
    mot_de_passe = donnees.get('mot_de_passe', '')

    conn = get_connection()
    utilisateur = conn.execute(
        'SELECT * FROM utilisateurs WHERE LOWER(identifiant) = LOWER(?) AND actif = 1',
        (identifiant,)
    ).fetchone()
    conn.close()

    if not utilisateur or not check_password_hash(utilisateur['mot_de_passe_hash'], mot_de_passe):
        return jsonify({'erreur': 'Identifiant ou mot de passe incorrect'}), 401

    token = generer_token(utilisateur['id'], utilisateur['role'])
    return jsonify({
        'token': token,
        'role': utilisateur['role'],
        'utilisateur_id': utilisateur['id']
    })


# ============================================================
# ACCÈS COMPTABLE (lecture seule sur la Gestion)
# ============================================================

# Pour un comptable, seules ces lectures sont possibles ; tout le reste est refusé, quelle que soit la route.
ROUTES_LECTURE_COMPTABLE = {'/api/facturation', '/api/facturation/groupees', '/api/pleins', '/api/achats'}


@app.before_request
def limiter_acces_comptable():
    """Verrou général : un jeton « comptable » ne peut que LIRE la Gestion, et seulement tant que son accès existe encore."""
    if not request.path.startswith('/api/') or request.method == 'OPTIONS':
        return None
    entete = request.headers.get('Authorization', '')
    if not entete.startswith('Bearer '):
        return None
    donnees = verifier_token(entete.removeprefix('Bearer ').strip())
    if not donnees or donnees.get('role') != 'comptable':
        return None
    conn = get_connection()
    acces = conn.execute('SELECT id, version FROM acces_comptable').fetchone()
    conn.close()
    if not acces or acces['id'] != donnees.get('utilisateur_id') or acces['version'] != donnees.get('v'):
        return jsonify({'erreur': 'Accès comptable révoqué ou expiré — reconnectez-vous'}), 401
    if request.method == 'GET' and (request.path.startswith('/api/gestion/') or request.path in ROUTES_LECTURE_COMPTABLE):
        return None
    return jsonify({'erreur': "Accès en lecture seule : cette action n'est pas autorisée pour le comptable"}), 403


@app.route('/api/auth/login-comptable', methods=['POST'])
def login_comptable():
    donnees = request.get_json(force=True) or {}
    identifiant = (donnees.get('identifiant') or '').strip()
    mot_de_passe = donnees.get('mot_de_passe') or ''
    conn = get_connection()
    acces = conn.execute('SELECT * FROM acces_comptable WHERE LOWER(identifiant) = LOWER(?)', (identifiant,)).fetchone()
    conn.close()
    if not acces or not check_password_hash(acces['mot_de_passe_hash'], mot_de_passe):
        return jsonify({'erreur': 'Identifiant ou mot de passe incorrect'}), 401
    token = serializer.dumps({'utilisateur_id': acces['id'], 'role': 'comptable', 'v': acces['version']})
    return jsonify({'token': token, 'role': 'comptable'})


@app.route('/api/gestion/acces-comptable', methods=['GET'])
@authentification_requise(['moderateur'])
def lire_acces_comptable():
    conn = get_connection()
    acces = conn.execute('SELECT identifiant, cree_le FROM acces_comptable').fetchone()
    conn.close()
    return jsonify({'actif': bool(acces), 'identifiant': acces['identifiant'] if acces else None})


@app.route('/api/gestion/acces-comptable', methods=['PUT'])
@authentification_requise(['moderateur'])
def enregistrer_acces_comptable():
    """Crée ou modifie l'unique accès comptable. Le mot de passe est obligatoire à la création, facultatif ensuite."""
    d = request.get_json(force=True) or {}
    identifiant = (d.get('identifiant') or '').strip()
    mot_de_passe = d.get('mot_de_passe') or ''
    if len(identifiant) < 3:
        return jsonify({'erreur': "L'identifiant doit faire au moins 3 caractères"}), 400
    conn = get_connection()
    existant = conn.execute('SELECT * FROM acces_comptable').fetchone()
    pris = conn.execute('SELECT 1 FROM utilisateurs WHERE LOWER(identifiant) = LOWER(?)', (identifiant,)).fetchone()
    if pris:
        conn.close()
        return jsonify({'erreur': 'Cet identifiant est déjà utilisé par un autre compte'}), 409
    if mot_de_passe and len(mot_de_passe) < 8:
        conn.close()
        return jsonify({'erreur': 'Le mot de passe doit faire au moins 8 caractères'}), 400
    if not existant:
        if not mot_de_passe:
            conn.close()
            return jsonify({'erreur': 'Un mot de passe est requis pour créer l\'accès'}), 400
        conn.execute('INSERT INTO acces_comptable (identifiant, mot_de_passe_hash) VALUES (?, ?)',
                     (identifiant, generate_password_hash(mot_de_passe)))
    else:
        if mot_de_passe:
            conn.execute('UPDATE acces_comptable SET identifiant = ?, mot_de_passe_hash = ?, version = version + 1 WHERE id = ?',
                         (identifiant, generate_password_hash(mot_de_passe), existant['id']))
        else:
            conn.execute('UPDATE acces_comptable SET identifiant = ?, version = version + 1 WHERE id = ?', (identifiant, existant['id']))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/gestion/acces-comptable', methods=['DELETE'])
@authentification_requise(['moderateur'])
def supprimer_acces_comptable():
    conn = get_connection()
    conn.execute('DELETE FROM acces_comptable')
    conn.commit()
    conn.close()
    return '', 204


# ============================================================
# CHAUFFEURS
# ============================================================

@app.route('/api/chauffeurs', methods=['GET'])
@authentification_requise()
def liste_chauffeurs():
    conn = get_connection()
    lignes = conn.execute('''
        SELECT c.*, t.immatriculation AS tracteur_immat, r.immatriculation AS remorque_immat
        FROM chauffeurs c
        LEFT JOIN tracteurs t ON t.id = c.tracteur_id
        LEFT JOIN remorques r ON r.id = c.remorque_id
        ORDER BY c.nom_complet
    ''').fetchall()
    conn.close()
    return jsonify([dict(l) for l in lignes])


@app.route('/api/chauffeurs', methods=['POST'])
@authentification_requise(['moderateur'])
def creer_chauffeur():
    donnees = request.get_json(force=True) or {}
    nom = donnees.get('nom_complet', '').strip()
    if not nom:
        return jsonify({'erreur': 'Le nom complet est requis'}), 400

    conn = get_connection()
    utilisateur_id = None

    # Création optionnelle du compte mobile en même temps
    identifiant = donnees.get('identifiant', '').strip()
    mot_de_passe = donnees.get('mot_de_passe', '').strip()
    if identifiant and mot_de_passe:
        existe = conn.execute('SELECT id FROM utilisateurs WHERE identifiant = ?', (identifiant,)).fetchone()
        if existe:
            conn.close()
            return jsonify({'erreur': "Cet identifiant est déjà utilisé"}), 409
        curseur = conn.execute(
            "INSERT INTO utilisateurs (identifiant, mot_de_passe_hash, role) VALUES (?, ?, 'chauffeur')",
            (identifiant, generate_password_hash(mot_de_passe))
        )
        utilisateur_id = curseur.lastrowid

    curseur = conn.execute(
        'INSERT INTO chauffeurs (utilisateur_id, nom_complet, telephone, numero_permis) VALUES (?, ?, ?, ?)',
        (utilisateur_id, nom, donnees.get('telephone'), donnees.get('numero_permis'))
    )
    conn.commit()
    chauffeur_id = curseur.lastrowid
    conn.close()
    return jsonify({'id': chauffeur_id, 'nom_complet': nom, 'utilisateur_id': utilisateur_id}), 201


@app.route('/api/chauffeurs/<int:chauffeur_id>', methods=['DELETE'])
@authentification_requise(['moderateur'])
def supprimer_chauffeur(chauffeur_id):
    conn = get_connection()
    # Libère aussi le compte mobile associé (sinon son identifiant reste bloqué indéfiniment)
    chauffeur = conn.execute('SELECT utilisateur_id FROM chauffeurs WHERE id = ?', (chauffeur_id,)).fetchone()
    conn.execute('DELETE FROM chauffeurs WHERE id = ?', (chauffeur_id,))
    if chauffeur and chauffeur['utilisateur_id']:
        conn.execute('DELETE FROM utilisateurs WHERE id = ?', (chauffeur['utilisateur_id'],))
    conn.commit()
    conn.close()
    return '', 204


@app.route('/api/chauffeurs/<int:chauffeur_id>/vehicule', methods=['PATCH'])
@authentification_requise()
def affecter_vehicule_chauffeur(chauffeur_id):
    donnees = request.get_json(force=True) or {}
    champs, valeurs = [], []
    # Le modérateur définit le véhicule ATTITRÉ (permanent) ; un chauffeur qui change lui-même
    # de véhicule ne modifie que celui du JOUR — son véhicule attitré n'est jamais touché, et
    # lui sera reproposé automatiquement dès sa prochaine clôture (voir declarer_km_arrivee).
    est_moderateur = g.user['role'] == 'moderateur'
    if 'tracteur_id' in donnees:
        champs.append('tracteur_id = ?')
        valeurs.append(donnees['tracteur_id'])
        if est_moderateur:
            champs.append('tracteur_attitre_id = ?')
            valeurs.append(donnees['tracteur_id'])
    if 'remorque_id' in donnees:
        champs.append('remorque_id = ?')
        valeurs.append(donnees['remorque_id'])
        if est_moderateur:
            champs.append('remorque_attitree_id = ?')
            valeurs.append(donnees['remorque_id'])
    if not champs:
        return jsonify({'erreur': 'Aucun champ à mettre à jour (tracteur_id ou remorque_id requis)'}), 400
    valeurs.append(chauffeur_id)
    conn = get_connection()
    conn.execute(f'UPDATE chauffeurs SET {", ".join(champs)} WHERE id = ?', valeurs)
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


# ============================================================
# TRACTEURS ROUTIERS
# ============================================================

@app.route('/api/tracteurs', methods=['GET'])
@authentification_requise()
def liste_tracteurs():
    conn = get_connection()
    lignes = conn.execute('SELECT * FROM tracteurs ORDER BY immatriculation').fetchall()
    conn.close()
    return jsonify([dict(l) for l in lignes])


@app.route('/api/tracteurs', methods=['POST'])
@authentification_requise(['moderateur'])
def creer_tracteur():
    donnees = request.get_json(force=True) or {}
    immat = donnees.get('immatriculation', '').strip()
    if not immat:
        return jsonify({'erreur': "L'immatriculation est requise"}), 400

    conn = get_connection()
    try:
        curseur = conn.execute(
            'INSERT INTO tracteurs (immatriculation, modele, kilometrage, date_controle_technique) VALUES (?, ?, ?, ?)',
            (immat, donnees.get('modele'), donnees.get('kilometrage', 0), donnees.get('date_controle_technique'))
        )
        conn.commit()
        tracteur_id = curseur.lastrowid
    except Exception:
        conn.close()
        return jsonify({'erreur': 'Cette immatriculation existe déjà'}), 409
    conn.close()
    return jsonify({'id': tracteur_id, 'immatriculation': immat}), 201


@app.route('/api/tracteurs/<int:tracteur_id>', methods=['DELETE'])
@authentification_requise(['moderateur'])
def supprimer_tracteur(tracteur_id):
    conn = get_connection()
    conn.execute('DELETE FROM tracteurs WHERE id = ?', (tracteur_id,))
    conn.commit()
    conn.close()
    return '', 204


# ============================================================
# REMORQUES
# ============================================================

@app.route('/api/remorques', methods=['GET'])
@authentification_requise()
def liste_remorques():
    conn = get_connection()
    lignes = conn.execute('''
        SELECT r.*, t.immatriculation AS tracteur_immat
        FROM remorques r LEFT JOIN tracteurs t ON t.id = r.tracteur_id
        ORDER BY r.immatriculation
    ''').fetchall()
    conn.close()
    return jsonify([dict(l) for l in lignes])


@app.route('/api/remorques', methods=['POST'])
@authentification_requise(['moderateur'])
def creer_remorque():
    donnees = request.get_json(force=True) or {}
    immat = donnees.get('immatriculation', '').strip()
    if not immat:
        return jsonify({'erreur': "L'immatriculation est requise"}), 400

    conn = get_connection()
    try:
        curseur = conn.execute(
            'INSERT INTO remorques (immatriculation, type, tracteur_id, date_controle_technique) VALUES (?, ?, ?, ?)',
            (immat, donnees.get('type'), donnees.get('tracteur_id'), donnees.get('date_controle_technique'))
        )
        conn.commit()
        remorque_id = curseur.lastrowid
    except Exception:
        conn.close()
        return jsonify({'erreur': 'Cette immatriculation existe déjà'}), 409
    conn.close()
    return jsonify({'id': remorque_id, 'immatriculation': immat}), 201


@app.route('/api/remorques/<int:remorque_id>', methods=['DELETE'])
@authentification_requise(['moderateur'])
def supprimer_remorque(remorque_id):
    conn = get_connection()
    conn.execute('DELETE FROM remorques WHERE id = ?', (remorque_id,))
    conn.commit()
    conn.close()
    return '', 204


# ============================================================
# CLIENTS
# ============================================================

@app.route('/api/clients', methods=['GET'])
@authentification_requise()
def liste_clients():
    conn = get_connection()
    lignes = conn.execute('SELECT * FROM clients ORDER BY nom').fetchall()
    conn.close()
    return jsonify([dict(l) for l in lignes])


@app.route('/api/clients', methods=['POST'])
@authentification_requise(['moderateur'])
def creer_client():
    donnees = request.get_json(force=True) or {}
    nom = (donnees.get('nom') or '').strip()
    if not nom:
        return jsonify({'erreur': 'Le nom du client est requis'}), 400
    conn = get_connection()
    if conn.execute('SELECT id FROM clients WHERE nom = ?', (nom,)).fetchone():
        conn.close()
        return jsonify({'erreur': 'Ce client existe déjà'}), 409
    curseur = conn.execute(
        'INSERT INTO clients (nom, adresse, contact) VALUES (?, ?, ?)',
        (nom, donnees.get('adresse'), donnees.get('contact'))
    )
    conn.commit()
    client_id = curseur.lastrowid
    conn.close()
    return jsonify({'id': client_id}), 201


@app.route('/api/clients/<int:client_id>', methods=['DELETE'])
@authentification_requise(['moderateur'])
def supprimer_client(client_id):
    conn = get_connection()
    conn.execute('DELETE FROM clients WHERE id = ?', (client_id,))
    conn.commit()
    conn.close()
    return '', 204


@app.route('/api/clients/<int:client_id>/bilan', methods=['GET'])
@authentification_requise(['moderateur'])
def bilan_client(client_id):
    """Renvoie toutes les missions réalisées pour ce client (tous chauffeurs confondus),
    avec le total de tours effectués — pour l'onglet Client du dashboard."""
    conn = get_connection()
    client = conn.execute('SELECT * FROM clients WHERE id = ?', (client_id,)).fetchone()
    if not client:
        conn.close()
        return jsonify({'erreur': 'Client introuvable'}), 404
    missions = conn.execute('''
        SELECT m.*, c.nom_complet AS chauffeur_nom
        FROM missions m JOIN chauffeurs c ON c.id = m.chauffeur_id
        WHERE m.client = ?
        ORDER BY m.date_mission DESC
    ''', (client['nom'],)).fetchall()
    conn.close()
    missions_liste = [dict(m) for m in missions]
    total_tours = sum(m['nombre_tours'] or 0 for m in missions_liste if m['realisee'])
    return jsonify({
        'client': dict(client),
        'missions': missions_liste,
        'total_tours': total_tours,
        'total_missions_realisees': len([m for m in missions_liste if m['realisee']])
    })


# ============================================================
# MISSIONS
# ============================================================

@app.route('/api/missions', methods=['GET'])
@authentification_requise()
def liste_missions():
    conn = get_connection()
    # Un chauffeur ne voit que ses propres missions ; un modérateur voit tout
    if g.user['role'] == 'chauffeur':
        chauffeur = conn.execute(
            'SELECT id FROM chauffeurs WHERE utilisateur_id = ?', (g.user['utilisateur_id'],)
        ).fetchone()
        if not chauffeur:
            conn.close()
            return jsonify([])
        lignes = conn.execute(
            'SELECT * FROM missions WHERE chauffeur_id = ? ORDER BY date_mission DESC',
            (chauffeur['id'],)
        ).fetchall()
    else:
        requete = '''
            SELECT m.*, c.nom_complet AS chauffeur_nom
            FROM missions m JOIN chauffeurs c ON c.id = m.chauffeur_id
            WHERE 1=1
        '''
        params = []
        chauffeur_id = request.args.get('chauffeur_id')
        mois = request.args.get('mois')
        if chauffeur_id:
            requete += ' AND m.chauffeur_id = ?'
            params.append(chauffeur_id)
        if mois:
            requete += ' AND m.date_mission LIKE ?'
            params.append(f'{mois}%')
        requete += ' ORDER BY m.date_mission DESC'
        lignes = conn.execute(requete, params).fetchall()
    conn.close()
    return jsonify([dict(l) for l in lignes])


@app.route('/api/missions', methods=['POST'])
@authentification_requise(['moderateur', 'chauffeur'])
def creer_mission():
    donnees = request.get_json(force=True) or {}

    chauffeur_id = donnees.get('chauffeur_id')
    if g.user['role'] == 'chauffeur':
        # Un chauffeur ne peut créer une mission QUE pour lui-même, jamais pour un autre
        chauffeur = _chauffeur_id_du_token()
        if not chauffeur:
            return jsonify({'erreur': 'Fiche chauffeur introuvable'}), 404
        chauffeur_id = chauffeur['id']

    if not chauffeur_id or not donnees.get('date_mission'):
        return jsonify({'erreur': 'chauffeur_id et date_mission sont requis'}), 400

    # Une mission créée pour le SEUL suivi du modérateur (ex. correction après un souci de saisie
    # côté chauffeur) est directement enregistrée comme déjà acceptée et réalisée — elle n'apparaît
    # donc jamais dans la liste "Missions" à accepter sur le téléphone du chauffeur.
    interne = bool(donnees.get('interne_seulement'))
    maintenant = datetime.now(FUSEAU_FR).strftime('%Y-%m-%d %H:%M:%S')

    conn = get_connection()
    curseur = conn.execute('''
        INSERT INTO missions (chauffeur_id, date_mission, heure_depart, client, adresse, chef_de_chantier,
                               acceptee, acceptee_le, realisee, realisee_le, statut, nombre_tours)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        chauffeur_id, donnees['date_mission'], donnees.get('heure_depart'),
        donnees.get('client'), donnees.get('adresse'), donnees.get('chef_de_chantier'),
        1 if interne else 0, maintenant if interne else None,
        1 if interne else 0, maintenant if interne else None,
        'livree' if interne else 'a_venir',
        donnees.get('nombre_tours') if interne else None
    ))
    conn.commit()
    mission_id = curseur.lastrowid

    # Crée aussi directement la ligne de facturation correspondante, comme le fait la validation
    # normale d'une mission — cohérent avec le fait qu'elle soit déjà marquée "réalisée".
    facturation_id = None
    if interne:
        curseur2 = conn.execute('''
            INSERT INTO facturation (mission_id, chauffeur_id, date_mission, client)
            VALUES (?, ?, ?, ?)
        ''', (mission_id, chauffeur_id, donnees['date_mission'], donnees.get('client')))
        conn.commit()
        facturation_id = curseur2.lastrowid

    conn.close()
    reponse = {'id': mission_id}
    if facturation_id:
        reponse['facturation_id'] = facturation_id
    return jsonify(reponse), 201


@app.route('/api/missions/<int:mission_id>/accepter', methods=['PATCH'])
@authentification_requise(['chauffeur'])
def accepter_mission(mission_id):
    conn = get_connection()
    conn.execute('''
        UPDATE missions SET acceptee = 1, acceptee_le = datetime('now'), statut = 'en_cours'
        WHERE id = ?
    ''', (mission_id,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/missions/<int:mission_id>/valider', methods=['PATCH'])
@authentification_requise(['chauffeur', 'moderateur'])
def valider_mission(mission_id):
    donnees = request.get_json(force=True) or {}
    conn = get_connection()
    conn.execute('''
        UPDATE missions
        SET realisee = 1, realisee_le = datetime('now'), statut = 'livree',
            nombre_tours = ?, remarque = ?
        WHERE id = ?
    ''', (donnees.get('nombre_tours'), donnees.get('remarque'), mission_id))
    conn.commit()

    # Création automatique de la ligne de facturation correspondante
    mission = conn.execute('SELECT * FROM missions WHERE id = ?', (mission_id,)).fetchone()
    facturation_id = None
    if mission:
        deja = conn.execute('SELECT id FROM facturation WHERE mission_id = ?', (mission_id,)).fetchone()
        if deja:
            facturation_id = deja['id']
        else:
            curseur = conn.execute('''
                INSERT INTO facturation (mission_id, chauffeur_id, date_mission, client)
                VALUES (?, ?, ?, ?)
            ''', (mission_id, mission['chauffeur_id'], mission['date_mission'], mission['client'] or 'Non renseigné'))
            facturation_id = curseur.lastrowid
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'facturation_id': facturation_id})


# ============================================================
# FACTURATION
# ============================================================

@app.route('/api/facturation', methods=['GET'])
@authentification_requise(['moderateur', 'comptable'])
def liste_facturation():
    conn = get_connection()
    lignes = conn.execute('''
        SELECT f.*, c.nom_complet AS chauffeur_nom
        FROM facturation f JOIN chauffeurs c ON c.id = f.chauffeur_id
        ORDER BY f.date_mission DESC
    ''').fetchall()
    conn.close()
    return jsonify([dict(l) for l in lignes])


@app.route('/api/facturation', methods=['POST'])
@authentification_requise(['moderateur'])
def creer_ligne_facturation():
    """Crée manuellement une ligne de facturation, sans mission associée (bouton
    « + Ajouter une ligne » du dashboard) — jusqu'ici cette action n'existait qu'en local dans
    le navigateur, jamais réellement enregistrée en base, d'où sa disparition à la reconnexion."""
    donnees = request.get_json(force=True) or {}
    if not donnees.get('chauffeur_id') or not donnees.get('date_mission') or not donnees.get('client'):
        return jsonify({'erreur': 'chauffeur_id, date_mission et client sont requis'}), 400
    conn = get_connection()
    curseur = conn.execute('''
        INSERT INTO facturation (chauffeur_id, date_mission, client)
        VALUES (?, ?, ?)
    ''', (donnees['chauffeur_id'], donnees['date_mission'], donnees['client']))
    conn.commit()
    ligne_id = curseur.lastrowid
    conn.close()
    return jsonify({'id': ligne_id}), 201


@app.route('/api/facturation/<int:ligne_id>', methods=['PATCH'])
@authentification_requise(['moderateur'])
def facturer_ligne(ligne_id):
    donnees = request.get_json(force=True) or {}
    champs, valeurs = [], []
    for champ in ('numero_facture', 'date_facturation', 'note', 'montant_ht', 'taux_tva'):
        if champ in donnees:
            champs.append(f'{champ} = ?')
            valeurs.append(donnees[champ])
    if not champs:
        return jsonify({'erreur': 'Aucun champ à mettre à jour'}), 400
    valeurs.append(ligne_id)
    conn = get_connection()
    conn.execute(f'UPDATE facturation SET {", ".join(champs)} WHERE id = ?', valeurs)
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/facturation/groupees', methods=['GET'])
@authentification_requise(['moderateur', 'comptable'])
def liste_factures_groupees():
    mois = request.args.get('mois')
    conn = get_connection()
    if mois:
        factures = conn.execute('SELECT * FROM factures_groupees WHERE mois = ? ORDER BY id DESC', (mois,)).fetchall()
    else:
        factures = conn.execute('SELECT * FROM factures_groupees ORDER BY id DESC').fetchall()
    resultat = []
    for f in factures:
        item = dict(f)
        item['nb_lignes'] = conn.execute('SELECT COUNT(*) AS n FROM facturation WHERE facture_groupee_id = ?', (f['id'],)).fetchone()['n']
        resultat.append(item)
    conn.close()
    return jsonify(resultat)


@app.route('/api/facturation/groupees', methods=['POST'])
@authentification_requise(['moderateur'])
def creer_facture_groupee():
    """Facture globale HT d'un mois pour les lignes encore « à facturer » (rouges) de un ou plusieurs
    clients, quand le prix n'est pas connu ligne par ligne (paiement au nombre de tours). Les lignes
    concernées passent en « facturées » ; le montant est porté par la facture globale, jamais deux fois."""
    d = request.get_json(force=True) or {}
    mois = d.get('mois')
    clients = d.get('clients') or []
    try:
        montant_ht = float(d.get('montant_ht'))
        taux = float(d.get('taux_tva', 20))
    except (TypeError, ValueError):
        return jsonify({'erreur': 'Montant HT ou taux de TVA invalide'}), 400
    if not mois or len(mois) != 7 or not clients:
        return jsonify({'erreur': 'Le mois et au moins un client sont requis'}), 400
    if montant_ht < 0 or taux < 0 or taux > 100:
        return jsonify({'erreur': 'Montant ou taux de TVA invalide'}), 400

    conn = get_connection()
    marques = ','.join('?' * len(clients))
    lignes = conn.execute(f'''
        SELECT id, client FROM facturation
        WHERE date_mission LIKE ? AND client IN ({marques})
          AND (numero_facture IS NULL OR numero_facture = '')
          AND montant_ht IS NULL AND facture_groupee_id IS NULL
    ''', (f'{mois}%', *clients)).fetchall()
    if not lignes:
        conn.close()
        return jsonify({'erreur': "Aucune ligne « à facturer » sans montant pour ces clients sur ce mois."}), 400

    date_facturation = d.get('date_facturation') or aujourdhui_fr()
    curseur = conn.execute(
        'INSERT INTO factures_groupees (mois, numero_facture, date_facturation, montant_ht, taux_tva, clients, note) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (mois, (d.get('numero_facture') or '').strip() or None, date_facturation, montant_ht, taux,
         ', '.join(sorted({l['client'] for l in lignes})), d.get('note')))
    facture_id = curseur.lastrowid
    numero = (d.get('numero_facture') or '').strip() or f'Facture globale n°{facture_id}'
    ids = [l['id'] for l in lignes]
    conn.execute(
        f'UPDATE facturation SET numero_facture = ?, date_facturation = ?, facture_groupee_id = ? WHERE id IN ({",".join("?" * len(ids))})',
        (numero, date_facturation, facture_id, *ids))
    conn.commit()
    conn.close()
    return jsonify({'id': facture_id, 'nb_lignes': len(ids)}), 201


@app.route('/api/facturation/groupees/<int:facture_id>', methods=['DELETE'])
@authentification_requise(['moderateur'])
def supprimer_facture_groupee(facture_id):
    """Supprime la facture globale et remet ses lignes « à facturer » (rouges)."""
    conn = get_connection()
    conn.execute(
        'UPDATE facturation SET numero_facture = NULL, date_facturation = NULL, facture_groupee_id = NULL WHERE facture_groupee_id = ?',
        (facture_id,))
    conn.execute('DELETE FROM factures_groupees WHERE id = ?', (facture_id,))
    conn.commit()
    conn.close()
    return '', 204


@app.route('/api/facturation/<int:ligne_id>', methods=['DELETE'])
@authentification_requise(['moderateur'])
def supprimer_facturation(ligne_id):
    conn = get_connection()
    conn.execute('DELETE FROM facturation WHERE id = ?', (ligne_id,))
    conn.commit()
    conn.close()
    return '', 204


# ============================================================
# DÉCLARATIONS DE JOURNÉE (prise de service, km départ/arrivée)
# ============================================================

def _chauffeur_id_du_token():
    """Retrouve l'id de la fiche chauffeur correspondant à l'utilisateur connecté."""
    conn = get_connection()
    ligne = conn.execute(
        'SELECT id, tracteur_id FROM chauffeurs WHERE utilisateur_id = ?', (g.user['utilisateur_id'],)
    ).fetchone()
    conn.close()
    return ligne


@app.route('/api/declarations', methods=['GET'])
@authentification_requise()
def liste_declarations():
    """Liste les déclarations de journée, filtrables par chauffeur_id et par mois (YYYY-MM)."""
    conn = get_connection()
    chauffeur_id = request.args.get('chauffeur_id')
    mois = request.args.get('mois')

    if g.user['role'] == 'chauffeur':
        c = _chauffeur_id_du_token()
        chauffeur_id = c['id'] if c else 0

    requete = '''
        SELECT d.*, t.immatriculation AS tracteur_immat
        FROM declarations_journee d LEFT JOIN tracteurs t ON t.id = d.tracteur_id
        WHERE 1=1
    '''
    params = []
    if chauffeur_id:
        requete += ' AND d.chauffeur_id = ?'
        params.append(chauffeur_id)
    if mois:
        requete += ' AND d.date_jour LIKE ?'
        params.append(f'{mois}%')
    requete += ' ORDER BY d.date_jour'
    lignes = conn.execute(requete, params).fetchall()
    conn.close()
    return jsonify([dict(l) for l in lignes])


@app.route('/api/declarations/aujourdhui', methods=['GET'])
@authentification_requise(['chauffeur'])
def declaration_du_jour():
    """Renvoie la déclaration du jour, et propose comme km de départ le kilométrage ACTUEL DU
    VÉHICULE lui-même (mis à jour à chaque clôture, quel que soit le chauffeur) — pas l'historique
    personnel du chauffeur connecté, qui casserait la suggestion dès qu'un véhicule change de main."""
    chauffeur = _chauffeur_id_du_token()
    if not chauffeur:
        return jsonify({'erreur': 'Fiche chauffeur introuvable'}), 404

    conn = get_connection()
    aujourdhui = request.args.get('date') or aujourdhui_fr()

    existante = conn.execute(
        'SELECT * FROM declarations_journee WHERE chauffeur_id = ? AND date_jour = ?',
        (chauffeur['id'], aujourdhui)
    ).fetchone()

    # Une journée n'est considérée "en cours" (rien à suggérer, km déjà figé) que si elle a un
    # départ SANS arrivée. Une fois clôturée (les deux renseignés), le cycle est refermé : le
    # kilométrage du véhicule redevient immédiatement la suggestion pour une réouverture — jamais
    # coincé sur le départ du matin jusqu'au passage à minuit.
    jour_en_cours = bool(existante and existante['km_depart'] is not None and existante['km_arrivee'] is None)

    km_depart_suggere = None
    if not jour_en_cours and chauffeur['tracteur_id']:
        tracteur = conn.execute(
            'SELECT kilometrage FROM tracteurs WHERE id = ?', (chauffeur['tracteur_id'],)
        ).fetchone()
        if tracteur and tracteur['kilometrage']:
            km_depart_suggere = tracteur['kilometrage']

    conn.close()
    return jsonify({
        'declaration': dict(existante) if jour_en_cours else None,
        'km_depart_suggere': km_depart_suggere
    })


def _date_journee_ouverte(conn, chauffeur_id):
    """Filet de sécurité côté serveur, utilisé seulement si le mobile n'a pas envoyé de date
    explicite (l'app envoie normalement toujours la sienne désormais). Retrouve la journée de
    travail EN COURS : celle où le kilométrage de départ est renseigné, mais pas encore celui
    d'arrivée. Si aucune journée n'est ouverte (jamais démarrée, ou déjà entièrement close),
    retombe sur la date d'aujourd'hui — jamais sur une ancienne journée déjà terminée, pour ne
    pas écraser par erreur une clôture précédente."""
    ouverte = conn.execute('''
        SELECT date_jour FROM declarations_journee
        WHERE chauffeur_id = ? AND km_depart IS NOT NULL AND km_arrivee IS NULL
        ORDER BY date_jour DESC LIMIT 1
    ''', (chauffeur_id,)).fetchone()
    if ouverte:
        return ouverte['date_jour']
    return aujourdhui_fr()


@app.route('/api/declarations/km-depart', methods=['POST'])
@authentification_requise(['chauffeur'])
def declarer_km_depart():
    chauffeur = _chauffeur_id_du_token()
    if not chauffeur:
        return jsonify({'erreur': 'Fiche chauffeur introuvable'}), 404
    donnees = request.get_json(force=True) or {}
    aujourdhui = donnees.get('date') or aujourdhui_fr()

    conn = get_connection()
    conn.execute('''
        INSERT INTO declarations_journee (chauffeur_id, date_jour, km_depart, tracteur_id, heure_prise_service)
        VALUES (?, ?, ?, ?, time('now'))
        ON CONFLICT(chauffeur_id, date_jour) DO UPDATE SET
            km_depart = excluded.km_depart,
            tracteur_id = excluded.tracteur_id
    ''', (chauffeur['id'], aujourdhui, donnees.get('km_depart'), chauffeur['tracteur_id']))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/declarations/km-arrivee', methods=['POST'])
@authentification_requise(['chauffeur'])
def declarer_km_arrivee():
    chauffeur = _chauffeur_id_du_token()
    if not chauffeur:
        return jsonify({'erreur': 'Fiche chauffeur introuvable'}), 404
    donnees = request.get_json(force=True) or {}
    conn = get_connection()
    aujourdhui = donnees.get('date') or _date_journee_ouverte(conn, chauffeur['id'])
    km_arrivee = donnees.get('km_arrivee')

    # INSERT/UPDATE (pas seulement UPDATE) : si le chauffeur a oublié de renseigner son
    # kilométrage de départ ce matin, la clôture du soir doit quand même fonctionner et créer
    # la ligne du jour — un simple UPDATE échouerait silencieusement (0 ligne à mettre à jour).
    conn.execute('''
        INSERT INTO declarations_journee (chauffeur_id, date_jour, km_arrivee, tracteur_id, heure_fin_service)
        VALUES (?, ?, ?, ?, time('now'))
        ON CONFLICT(chauffeur_id, date_jour) DO UPDATE SET
            km_arrivee = excluded.km_arrivee,
            heure_fin_service = excluded.heure_fin_service
    ''', (chauffeur['id'], aujourdhui, km_arrivee, chauffeur['tracteur_id']))

    # Répercute ce kilométrage sur la fiche du véhicule attitré, dans l'onglet Véhicules du dashboard —
    # seulement s'il progresse (jamais en arrière, pour ne pas écraser une valeur juste avec une erreur).
    if chauffeur['tracteur_id'] and km_arrivee is not None:
        conn.execute('''
            UPDATE tracteurs SET kilometrage = ?
            WHERE id = ? AND (kilometrage IS NULL OR kilometrage < ?)
        ''', (km_arrivee, chauffeur['tracteur_id'], km_arrivee))

    # Le véhicule redevient immédiatement disponible : le chauffeur retrouve son véhicule attitré
    # dès sa clôture, sans jamais attendre le passage à minuit. Ça évite tout croisement quand un
    # véhicule change de chauffeur en cours de service (ex. relève à 18h, fin à 3h le lendemain).
    conn.execute(
        'UPDATE chauffeurs SET tracteur_id = tracteur_attitre_id, remorque_id = remorque_attitree_id WHERE id = ?',
        (chauffeur['id'],)
    )

    conn.commit()
    conn.close()
    return jsonify({'ok': True})


# ============================================================
# INDEMNITÉS (frais de route)
# ============================================================

TARIFS_INDEMNITES = {
    'casse_croute': 8.87, 'repas_nuit': 9.81, 'repas': 16.36,
    'petit_decouche': 52.31, 'grand_decouche': 68.67
}


@app.route('/api/indemnites', methods=['GET'])
@authentification_requise()
def liste_indemnites():
    conn = get_connection()
    mois = request.args.get('mois')  # format 'YYYY-MM'
    if g.user['role'] == 'chauffeur':
        chauffeur = _chauffeur_id_du_token()
        requete = 'SELECT * FROM indemnites WHERE chauffeur_id = ?'
        params = [chauffeur['id']] if chauffeur else [0]
    else:
        requete = '''SELECT i.*, c.nom_complet AS chauffeur_nom FROM indemnites i
                     JOIN chauffeurs c ON c.id = i.chauffeur_id WHERE 1=1'''
        params = []
        chauffeur_id_filtre = request.args.get('chauffeur_id')
        if chauffeur_id_filtre:
            requete += ' AND i.chauffeur_id = ?'
            params.append(chauffeur_id_filtre)
    if mois:
        requete += " AND date_jour LIKE ?"
        params.append(f'{mois}%')
    lignes = conn.execute(requete, params).fetchall()
    conn.close()

    resultat = []
    for l in lignes:
        d = dict(l)
        total = sum(TARIFS_INDEMNITES[cle] for cle in TARIFS_INDEMNITES if d.get(cle))
        d['total'] = round(total, 2)
        resultat.append(d)
    return jsonify(resultat)


@app.route('/api/indemnites', methods=['POST'])
@authentification_requise(['chauffeur'])
def declarer_indemnites():
    chauffeur = _chauffeur_id_du_token()
    if not chauffeur:
        return jsonify({'erreur': 'Fiche chauffeur introuvable'}), 404
    donnees = request.get_json(force=True) or {}
    conn = get_connection()
    aujourdhui = donnees.get('date') or _date_journee_ouverte(conn, chauffeur['id'])

    conn.execute('''
        INSERT INTO indemnites (chauffeur_id, date_jour, casse_croute, repas_nuit, repas, petit_decouche, grand_decouche, commentaire)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(chauffeur_id, date_jour) DO UPDATE SET
            casse_croute=excluded.casse_croute, repas_nuit=excluded.repas_nuit, repas=excluded.repas,
            petit_decouche=excluded.petit_decouche, grand_decouche=excluded.grand_decouche, commentaire=excluded.commentaire
    ''', (
        chauffeur['id'], aujourdhui,
        int(bool(donnees.get('casse_croute'))), int(bool(donnees.get('repas_nuit'))), int(bool(donnees.get('repas'))),
        int(bool(donnees.get('petit_decouche'))), int(bool(donnees.get('grand_decouche'))), donnees.get('commentaire')
    ))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/planning/journee', methods=['PUT'])
@authentification_requise(['moderateur'])
def corriger_journee():
    """Correction manuelle d'une journée par le modérateur (en cas de défaillance du chauffeur).
    Écrit dans les MÊMES tables que l'application mobile (indemnites, declarations_journee,
    kilométrage du véhicule) : tous les onglets se mettent donc à jour comme si le chauffeur
    avait saisi lui-même."""
    d = request.get_json(force=True) or {}
    chauffeur_id = d.get('chauffeur_id')
    date_jour = d.get('date_jour')
    if not chauffeur_id or not date_jour:
        return jsonify({'erreur': 'chauffeur_id et date_jour sont requis'}), 400

    conn = get_connection()
    chauffeur = conn.execute('SELECT * FROM chauffeurs WHERE id = ?', (chauffeur_id,)).fetchone()
    if not chauffeur:
        conn.close()
        return jsonify({'erreur': 'Chauffeur introuvable'}), 404

    # --- Indemnités ---
    if d.get('indemnites') is not None:
        ind = d['indemnites']
        valeurs = [int(bool(ind.get(cle))) for cle in TARIFS_INDEMNITES]
        if any(valeurs):
            conn.execute('''
                INSERT INTO indemnites (chauffeur_id, date_jour, casse_croute, repas_nuit, repas, petit_decouche, grand_decouche)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chauffeur_id, date_jour) DO UPDATE SET
                    casse_croute=excluded.casse_croute, repas_nuit=excluded.repas_nuit, repas=excluded.repas,
                    petit_decouche=excluded.petit_decouche, grand_decouche=excluded.grand_decouche
            ''', (chauffeur_id, date_jour, *[int(bool(ind.get(cle))) for cle in
                   ('casse_croute', 'repas_nuit', 'repas', 'petit_decouche', 'grand_decouche')]))
        else:
            conn.execute('DELETE FROM indemnites WHERE chauffeur_id = ? AND date_jour = ?', (chauffeur_id, date_jour))

    # --- Kilomètres parcourus ---
    if d.get('km_parcourus') is not None:
        try:
            km = int(d['km_parcourus'])
        except (TypeError, ValueError):
            conn.close()
            return jsonify({'erreur': 'Kilomètres invalides'}), 400
        if km < 0:
            conn.close()
            return jsonify({'erreur': 'Les kilomètres ne peuvent pas être négatifs'}), 400

        decl = conn.execute(
            'SELECT * FROM declarations_journee WHERE chauffeur_id = ? AND date_jour = ?', (chauffeur_id, date_jour)
        ).fetchone()
        tracteur_id = (decl['tracteur_id'] if decl else None) or chauffeur['tracteur_attitre_id'] or chauffeur['tracteur_id']
        if not tracteur_id:
            conn.close()
            return jsonify({'erreur': "Ce chauffeur n'a aucun véhicule attitré : impossible de rattacher les kilomètres."}), 400

        # Point de départ = dernière clôture de CE VÉHICULE avant ce jour (même logique que le
        # calcul du Planning mensuel), sinon le départ déjà saisi, sinon le kilométrage actuel du véhicule.
        prec = conn.execute('''
            SELECT km_arrivee FROM declarations_journee
            WHERE tracteur_id = ? AND km_arrivee IS NOT NULL AND date_jour < ?
            ORDER BY date_jour DESC, COALESCE(heure_fin_service, '23:59:59') DESC LIMIT 1
        ''', (tracteur_id, date_jour)).fetchone()
        attitre = chauffeur['tracteur_attitre_id']
        changement = attitre is not None and tracteur_id != attitre
        if changement and decl and decl['km_depart'] is not None:
            base = decl['km_depart']
        elif prec:
            base = prec['km_arrivee']
        elif decl and decl['km_depart'] is not None:
            base = decl['km_depart']
        else:
            plus_tard = conn.execute(
                'SELECT 1 FROM declarations_journee WHERE tracteur_id = ? AND date_jour > ? AND km_arrivee IS NOT NULL LIMIT 1',
                (tracteur_id, date_jour)).fetchone()
            trac = conn.execute('SELECT kilometrage FROM tracteurs WHERE id = ?', (tracteur_id,)).fetchone()
            if plus_tard or not trac or not trac['kilometrage']:
                conn.close()
                return jsonify({'erreur': "Aucun kilométrage de référence pour ce véhicule avant cette date : saisissez d'abord le kilométrage du véhicule dans l'onglet Véhicules."}), 400
            base = trac['kilometrage']

        km_depart = decl['km_depart'] if decl and decl['km_depart'] is not None else base
        km_arrivee = base + km
        conn.execute('''
            INSERT INTO declarations_journee (chauffeur_id, date_jour, km_depart, km_arrivee, tracteur_id)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(chauffeur_id, date_jour) DO UPDATE SET
                km_depart = excluded.km_depart, km_arrivee = excluded.km_arrivee, tracteur_id = excluded.tracteur_id
        ''', (chauffeur_id, date_jour, km_depart, km_arrivee, tracteur_id))
        conn.execute('''
            UPDATE tracteurs SET kilometrage = ?
            WHERE id = ? AND (kilometrage IS NULL OR kilometrage < ?)
        ''', (km_arrivee, tracteur_id, km_arrivee))

    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/cloture-jour/<int:chauffeur_id>/<date_jour>', methods=['DELETE'])
@authentification_requise(['moderateur'])
def supprimer_cloture_jour(chauffeur_id, date_jour):
    """Supprime la ligne complète d'une journée pour un chauffeur : sa déclaration
    (kilométrage départ/arrivée) ET ses indemnités de ce jour, ensemble."""
    conn = get_connection()
    conn.execute('DELETE FROM declarations_journee WHERE chauffeur_id = ? AND date_jour = ?', (chauffeur_id, date_jour))
    conn.execute('DELETE FROM indemnites WHERE chauffeur_id = ? AND date_jour = ?', (chauffeur_id, date_jour))
    conn.commit()
    conn.close()
    return '', 204


# ============================================================
# ACHATS (pro / perso)
# ============================================================

# Types d'achats professionnels et taux de TVA qui en découlent (le chauffeur choisit le type,
# la TVA est déduite automatiquement ; le modérateur peut la corriger ligne par ligne).
CATEGORIES_ACHATS = [
    ('Repas / restaurant', 10),
    ('Hébergement (hôtel)', 10),
    ('Courses alimentaires (à emporter)', 5.5),
    ('Péages', 20),
    ('Parking', 20),
    ('Lavage', 20),
    ('Entretien / réparation', 20),
    ('Pneumatiques', 20),
    ('Fournitures / pièces', 20),
    ('Autre', 20),
]
TAUX_PAR_CATEGORIE = dict(CATEGORIES_ACHATS)


@app.route('/api/achats/categories', methods=['GET'])
@authentification_requise(['moderateur', 'chauffeur'])
def categories_achats():
    return jsonify([{'nom': n, 'taux_tva': t} for n, t in CATEGORIES_ACHATS])


@app.route('/api/achats/<int:achat_id>', methods=['PATCH'])
@authentification_requise(['moderateur'])
def modifier_achat(achat_id):
    """Le modérateur corrige le type d'achat et/ou le taux de TVA d'un achat."""
    d = request.get_json(force=True) or {}
    champs, valeurs = [], []
    if 'taux_tva' in d:
        try:
            taux = float(d['taux_tva'])
        except (TypeError, ValueError):
            return jsonify({'erreur': 'Taux de TVA invalide'}), 400
        if taux < 0 or taux > 100:
            return jsonify({'erreur': 'Le taux de TVA doit être entre 0 et 100'}), 400
        champs.append('taux_tva = ?'); valeurs.append(taux)
    if 'categorie' in d:
        champs.append('categorie = ?'); valeurs.append(d['categorie'] or None)
        # Changer le type d'un achat déjà effectué en déduit aussitôt la TVA (sauf si un taux est imposé)
        if 'taux_tva' not in d and d['categorie'] in TAUX_PAR_CATEGORIE:
            champs.append('taux_tva = ?'); valeurs.append(TAUX_PAR_CATEGORIE[d['categorie']])
    if not champs:
        return jsonify({'erreur': 'Aucun champ à modifier'}), 400
    valeurs.append(achat_id)
    conn = get_connection()
    conn.execute(f'UPDATE achats SET {", ".join(champs)} WHERE id = ?', valeurs)
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/achats', methods=['GET'])
@authentification_requise()
def liste_achats():
    conn = get_connection()
    type_filtre = request.args.get('type')  # 'pro' ou 'perso'
    mois = request.args.get('mois')
    if g.user['role'] == 'chauffeur':
        chauffeur = _chauffeur_id_du_token()
        requete = 'SELECT * FROM achats WHERE chauffeur_id = ?'
        params = [chauffeur['id']] if chauffeur else [0]
    else:
        requete = '''SELECT a.*, c.nom_complet AS chauffeur_nom FROM achats a
                     JOIN chauffeurs c ON c.id = a.chauffeur_id WHERE 1=1'''
        params = []
    if type_filtre:
        requete += ' AND type = ?'
        params.append(type_filtre)
    if mois:
        requete += ' AND date_achat LIKE ?'
        params.append(f'{mois}%')
    requete += ' ORDER BY date_achat DESC'
    lignes = conn.execute(requete, params).fetchall()
    taux_defaut = float(_lire_parametres(conn)['tva_achats_pro'])
    conn.close()
    resultat = []
    for l in lignes:
        item = dict(l)
        # Taux réellement appliqué : celui de l'achat, sinon le taux par défaut (anciens achats sans type)
        item['taux_effectif'] = item['taux_tva'] if item.get('taux_tva') is not None else taux_defaut
        resultat.append(item)
    return jsonify(resultat)


@app.route('/api/achats', methods=['POST'])
@authentification_requise(['chauffeur'])
def declarer_achat():
    chauffeur = _chauffeur_id_du_token()
    if not chauffeur:
        return jsonify({'erreur': 'Fiche chauffeur introuvable'}), 404
    donnees = request.get_json(force=True) or {}
    if donnees.get('type') not in ('pro', 'perso') or not donnees.get('montant'):
        return jsonify({'erreur': 'type (pro/perso) et montant sont requis'}), 400

    conn = get_connection()
    categorie = donnees.get('categorie') if donnees['type'] == 'pro' else None
    taux = None
    if categorie:
        taux = TAUX_PAR_CATEGORIE.get(categorie)
        if taux is None:   # type inconnu : on le garde tel quel, avec le taux par défaut des achats pro
            taux = float(_lire_parametres(conn)['tva_achats_pro'])
    curseur = conn.execute('''
        INSERT INTO achats (chauffeur_id, type, date_achat, description, montant, categorie, taux_tva)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        chauffeur['id'], donnees['type'],
        donnees.get('date_achat') or aujourdhui_fr(),
        donnees.get('description'), float(donnees['montant']), categorie, taux
    ))
    conn.commit()
    achat_id = curseur.lastrowid
    conn.close()
    return jsonify({'id': achat_id}), 201


@app.route('/api/achats/<int:achat_id>', methods=['DELETE'])
@authentification_requise(['moderateur'])
def supprimer_achat(achat_id):
    conn = get_connection()
    conn.execute('DELETE FROM achats WHERE id = ?', (achat_id,))
    conn.commit()
    conn.close()
    return '', 204


# ============================================================
# PLEINS DE CARBURANT + TICPE
# ============================================================

@app.route('/api/pleins', methods=['GET'])
@authentification_requise()
def liste_pleins():
    conn = get_connection()
    tracteur_id = request.args.get('tracteur_id')
    chauffeur_id = request.args.get('chauffeur_id')
    type_carburant = request.args.get('type_carburant')

    if g.user['role'] == 'chauffeur':
        # Un chauffeur ne voit JAMAIS les pleins d'un autre véhicule ou d'un autre chauffeur,
        # même s'il tente de le demander via les paramètres — on force son propre tracteur.
        chauffeur = _chauffeur_id_du_token()
        if not chauffeur or not chauffeur['tracteur_id']:
            conn.close()
            return jsonify([])
        tracteur_id = chauffeur['tracteur_id']
        chauffeur_id = None

    requete = '''SELECT p.*, t.immatriculation AS tracteur_immat, c.nom_complet AS chauffeur_nom
                 FROM pleins_carburant p
                 JOIN tracteurs t ON t.id = p.tracteur_id
                 LEFT JOIN chauffeurs c ON c.id = p.chauffeur_id WHERE 1=1'''
    params = []
    if tracteur_id:
        requete += ' AND p.tracteur_id = ?'
        params.append(tracteur_id)
    if chauffeur_id:
        requete += ' AND p.chauffeur_id = ?'
        params.append(chauffeur_id)
    if type_carburant:
        requete += ' AND p.type_carburant = ?'
        params.append(type_carburant)
    requete += ' ORDER BY p.date_plein DESC'
    lignes = conn.execute(requete, params).fetchall()
    conn.close()
    return jsonify([dict(l) for l in lignes])


@app.route('/api/pleins', methods=['POST'])
@authentification_requise()
def creer_plein():
    donnees = request.get_json(force=True) or {}
    if not donnees.get('tracteur_id') or not donnees.get('date_plein'):
        return jsonify({'erreur': 'tracteur_id et date_plein sont requis'}), 400

    chauffeur_id = donnees.get('chauffeur_id')
    if g.user['role'] == 'chauffeur' and not chauffeur_id:
        c = _chauffeur_id_du_token()
        chauffeur_id = c['id'] if c else None

    conn = get_connection()
    curseur = conn.execute('''
        INSERT INTO pleins_carburant (tracteur_id, chauffeur_id, type_carburant, date_plein, kilometrage, litres, prix_total)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        donnees['tracteur_id'], chauffeur_id, donnees.get('type_carburant', 'gazoil'), donnees['date_plein'],
        donnees.get('kilometrage'), donnees.get('litres'), donnees.get('prix_total')
    ))
    conn.commit()
    plein_id = curseur.lastrowid
    conn.close()
    return jsonify({'id': plein_id}), 201


@app.route('/api/pleins/<int:plein_id>', methods=['PATCH'])
@authentification_requise(['moderateur'])
def modifier_plein(plein_id):
    """Corrige un plein mal renseigné (litrage, kilométrage, prix, date) depuis le dashboard."""
    donnees = request.get_json(force=True) or {}
    champs_autorises = ['litres', 'kilometrage', 'prix_total', 'date_plein']
    a_modifier = {k: v for k, v in donnees.items() if k in champs_autorises}
    if not a_modifier:
        return jsonify({'erreur': 'Aucun champ valide à modifier'}), 400

    conn = get_connection()
    assignations = ', '.join(f'{champ} = ?' for champ in a_modifier)
    conn.execute(f'UPDATE pleins_carburant SET {assignations} WHERE id = ?', (*a_modifier.values(), plein_id))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/pleins/<int:plein_id>', methods=['DELETE'])
@authentification_requise(['moderateur'])
def supprimer_plein(plein_id):
    conn = get_connection()
    conn.execute('DELETE FROM pleins_carburant WHERE id = ?', (plein_id,))
    conn.commit()
    conn.close()
    return '', 204


@app.route('/api/pleins/ticpe', methods=['GET'])
@authentification_requise(['moderateur'])
def ticpe_litrage():
    """Litrage total par tracteur, groupé par mois (YYYY-MM), pour une année donnée."""
    annee = request.args.get('annee', str(datetime.now(FUSEAU_FR).year))
    conn = get_connection()
    lignes = conn.execute('''
        SELECT t.immatriculation, strftime('%m', p.date_plein) AS mois, SUM(p.litres) AS total_litres
        FROM pleins_carburant p JOIN tracteurs t ON t.id = p.tracteur_id
        WHERE strftime('%Y', p.date_plein) = ? AND p.type_carburant = 'gazoil'
        GROUP BY t.immatriculation, mois
        ORDER BY t.immatriculation, mois
    ''', (annee,)).fetchall()
    conn.close()
    return jsonify([dict(l) for l in lignes])


# ============================================================
# DOCUMENTS (chauffeurs et véhicules)
# ============================================================

@app.route('/api/documents/chauffeurs/<int:chauffeur_id>', methods=['PUT'])
@authentification_requise(['moderateur'])
def enregistrer_documents_chauffeur(chauffeur_id):
    donnees = request.get_json(force=True) or {}
    conn = get_connection()
    conn.execute('''
        INSERT INTO documents_chauffeurs (chauffeur_id, carte_identite, permis, passeport, carte_conducteur, adr, chronotachygraphe)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(chauffeur_id) DO UPDATE SET
            carte_identite=excluded.carte_identite, permis=excluded.permis, passeport=excluded.passeport,
            carte_conducteur=excluded.carte_conducteur, adr=excluded.adr, chronotachygraphe=excluded.chronotachygraphe
    ''', (
        chauffeur_id, donnees.get('carte_identite'), donnees.get('permis'), donnees.get('passeport'),
        donnees.get('carte_conducteur'), donnees.get('adr'), donnees.get('chronotachygraphe')
    ))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/documents/chauffeurs', methods=['GET'])
@authentification_requise(['moderateur'])
def liste_documents_chauffeurs():
    conn = get_connection()
    lignes = conn.execute('''
        SELECT c.id AS chauffeur_id, c.nom_complet, d.*
        FROM chauffeurs c LEFT JOIN documents_chauffeurs d ON d.chauffeur_id = c.id
    ''').fetchall()
    conn.close()
    return jsonify([dict(l) for l in lignes])


@app.route('/api/documents/chauffeurs/me', methods=['GET'])
@authentification_requise(['chauffeur'])
def mes_documents_chauffeur():
    """Un chauffeur ne peut consulter que SES PROPRES documents, jamais ceux d'un autre."""
    chauffeur = _chauffeur_id_du_token()
    if not chauffeur:
        return jsonify({'erreur': 'Fiche chauffeur introuvable'}), 404
    conn = get_connection()
    ligne = conn.execute(
        'SELECT * FROM documents_chauffeurs WHERE chauffeur_id = ?', (chauffeur['id'],)
    ).fetchone()
    conn.close()
    return jsonify(dict(ligne) if ligne else {})


@app.route('/api/documents/remorques/<int:remorque_id>', methods=['PUT'])
@authentification_requise(['moderateur'])
def enregistrer_documents_remorque(remorque_id):
    donnees = request.get_json(force=True) or {}
    conn = get_connection()
    conn.execute('''
        UPDATE remorques SET date_assurance = ?, date_controle_technique = ?,
               date_extincteur = ?, date_chronotachygraphe = ?, date_tachylimiteur = ?
        WHERE id = ?
    ''', (
        donnees.get('date_assurance'), donnees.get('date_controle_technique'),
        donnees.get('date_extincteur'), donnees.get('date_chronotachygraphe'),
        donnees.get('date_tachylimiteur'), remorque_id
    ))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/documents/tracteurs/<int:tracteur_id>', methods=['PUT'])
@authentification_requise(['moderateur'])
def enregistrer_documents_tracteur(tracteur_id):
    donnees = request.get_json(force=True) or {}
    conn = get_connection()
    conn.execute('''
        UPDATE tracteurs SET date_assurance = ?, date_controle_technique = ?,
               date_extincteur = ?, date_chronotachygraphe = ?, date_tachylimiteur = ?
        WHERE id = ?
    ''', (
        donnees.get('date_assurance'), donnees.get('date_controle_technique'),
        donnees.get('date_extincteur'), donnees.get('date_chronotachygraphe'),
        donnees.get('date_tachylimiteur'), tracteur_id
    ))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


# ============================================================
# HISTORIQUE (vue combinée : missions + frais)
# ============================================================

@app.route('/api/historique', methods=['GET'])
@authentification_requise(['moderateur'])
def historique():
    conn = get_connection()
    missions = conn.execute('''
        SELECT 'mission' AS type, m.id AS id, m.chauffeur_id AS chauffeur_id, m.date_mission AS date,
               c.nom_complet AS chauffeur, m.client AS detail, m.statut AS info
        FROM missions m JOIN chauffeurs c ON c.id = m.chauffeur_id
    ''').fetchall()
    frais = conn.execute('''
        SELECT 'frais' AS type, i.id AS id, i.chauffeur_id AS chauffeur_id, i.date_jour AS date,
               c.nom_complet AS chauffeur, 'Indemnités' AS detail, '' AS info
        FROM indemnites i JOIN chauffeurs c ON c.id = i.chauffeur_id
    ''').fetchall()
    conn.close()
    combine = [dict(l) for l in missions] + [dict(l) for l in frais]
    combine.sort(key=lambda x: x['date'], reverse=True)
    return jsonify(combine)


# ============================================================
# MISES À JOUR FINES (kilométrage, rendez-vous de contrôle technique)
# ============================================================

@app.route('/api/tracteurs/<int:tracteur_id>', methods=['PATCH'])
@authentification_requise(['moderateur'])
def modifier_tracteur(tracteur_id):
    donnees = request.get_json(force=True) or {}
    champs_autorises = [
        'modele', 'kilometrage', 'date_controle_technique', 'date_rdv_controle_technique',
        'date_assurance', 'date_extincteur', 'date_chronotachygraphe', 'date_tachylimiteur'
    ]
    a_modifier = {k: v for k, v in donnees.items() if k in champs_autorises}
    if not a_modifier:
        return jsonify({'erreur': 'Aucun champ valide à modifier'}), 400

    conn = get_connection()
    assignations = ', '.join(f'{champ} = ?' for champ in a_modifier)
    conn.execute(f'UPDATE tracteurs SET {assignations} WHERE id = ?', (*a_modifier.values(), tracteur_id))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/remorques/<int:remorque_id>', methods=['PATCH'])
@authentification_requise(['moderateur'])
def modifier_remorque(remorque_id):
    donnees = request.get_json(force=True) or {}
    champs_autorises = ['type', 'tracteur_id', 'date_controle_technique', 'date_rdv_controle_technique']
    a_modifier = {k: v for k, v in donnees.items() if k in champs_autorises}
    if not a_modifier:
        return jsonify({'erreur': 'Aucun champ valide à modifier'}), 400

    conn = get_connection()
    assignations = ', '.join(f'{champ} = ?' for champ in a_modifier)
    conn.execute(f'UPDATE remorques SET {assignations} WHERE id = ?', (*a_modifier.values(), remorque_id))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/missions/<int:mission_id>', methods=['PATCH'])
@authentification_requise(['moderateur'])
def modifier_mission(mission_id):
    donnees = request.get_json(force=True) or {}
    champs_autorises = ['date_mission', 'heure_depart', 'client', 'adresse', 'chef_de_chantier', 'statut', 'nombre_tours']
    a_modifier = {k: v for k, v in donnees.items() if k in champs_autorises}
    if not a_modifier and 'realisee' not in donnees:
        return jsonify({'erreur': 'Aucun champ valide à modifier'}), 400

    conn = get_connection()

    # Marquer une mission réalisée / non réalisée à la main (correction par le modérateur) :
    # exactement le même effet que si le chauffeur l'avait validée sur son téléphone —
    # ligne de facturation créée, ou retirée si elle n'a pas encore de numéro de facture.
    if 'realisee' in donnees:
        maintenant = datetime.now(FUSEAU_FR).strftime('%Y-%m-%d %H:%M:%S')
        if donnees['realisee']:
            conn.execute('''
                UPDATE missions SET realisee = 1, realisee_le = COALESCE(realisee_le, ?),
                    acceptee = 1, acceptee_le = COALESCE(acceptee_le, ?), statut = 'livree'
                WHERE id = ?
            ''', (maintenant, maintenant, mission_id))
            mission = conn.execute('SELECT * FROM missions WHERE id = ?', (mission_id,)).fetchone()
            if mission and not conn.execute('SELECT id FROM facturation WHERE mission_id = ?', (mission_id,)).fetchone():
                conn.execute('''
                    INSERT INTO facturation (mission_id, chauffeur_id, date_mission, client)
                    VALUES (?, ?, ?, ?)
                ''', (mission_id, mission['chauffeur_id'], mission['date_mission'], mission['client'] or 'Non renseigné'))
        else:
            conn.execute('''
                UPDATE missions SET realisee = 0, realisee_le = NULL, statut = 'en_cours'
                WHERE id = ?
            ''', (mission_id,))
            conn.execute('DELETE FROM facturation WHERE mission_id = ? AND numero_facture IS NULL', (mission_id,))
        conn.commit()
        if not a_modifier:
            conn.close()
            return jsonify({'ok': True})

    assignations = ', '.join(f'{champ} = ?' for champ in a_modifier)
    conn.execute(f'UPDATE missions SET {assignations} WHERE id = ?', (*a_modifier.values(), mission_id))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/missions/<int:mission_id>', methods=['DELETE'])
@authentification_requise(['moderateur'])
def supprimer_mission(mission_id):
    conn = get_connection()
    # Supprime aussi la ligne de facturation associée, SAUF si elle a déjà un numéro de facture
    # (dans ce cas, on la laisse : une facture déjà émise ne doit jamais disparaître silencieusement).
    conn.execute(
        'DELETE FROM facturation WHERE mission_id = ? AND numero_facture IS NULL',
        (mission_id,)
    )
    conn.execute('DELETE FROM missions WHERE id = ?', (mission_id,))
    conn.commit()
    conn.close()
    return '', 204


@app.route('/api/utilisateurs/<int:utilisateur_id>/mot-de-passe', methods=['PATCH'])
@authentification_requise(['moderateur'])
def reinitialiser_mot_de_passe(utilisateur_id):
    donnees = request.get_json(force=True) or {}
    nouveau = donnees.get('mot_de_passe', '').strip()
    if not nouveau:
        return jsonify({'erreur': 'Nouveau mot de passe requis'}), 400
    conn = get_connection()
    conn.execute(
        'UPDATE utilisateurs SET mot_de_passe_hash = ? WHERE id = ?',
        (generate_password_hash(nouveau), utilisateur_id)
    )
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/utilisateurs/<int:utilisateur_id>', methods=['DELETE'])
@authentification_requise(['moderateur'])
def desactiver_compte(utilisateur_id):
    """Désactive un compte plutôt que de le supprimer (conserve l'historique lié)."""
    conn = get_connection()
    conn.execute('UPDATE utilisateurs SET actif = 0 WHERE id = ?', (utilisateur_id,))
    conn.commit()
    conn.close()
    return '', 204


@app.route('/api/utilisateurs/<int:utilisateur_id>/liberer', methods=['DELETE'])
@authentification_requise(['moderateur'])
def liberer_identifiant(utilisateur_id):
    """Supprime réellement un compte orphelin (sans chauffeur associé), pour libérer son identifiant.
    Refuse la suppression si un chauffeur est encore relié, pour ne jamais perdre de données réelles."""
    conn = get_connection()
    chauffeur_lie = conn.execute('SELECT id FROM chauffeurs WHERE utilisateur_id = ?', (utilisateur_id,)).fetchone()
    if chauffeur_lie:
        conn.close()
        return jsonify({'erreur': 'Ce compte est encore relié à un chauffeur — supprimez plutôt le chauffeur, ou désactivez le compte.'}), 409
    conn.execute('DELETE FROM utilisateurs WHERE id = ?', (utilisateur_id,))
    conn.commit()
    conn.close()
    return '', 204


@app.route('/api/utilisateurs', methods=['GET'])
@authentification_requise(['moderateur'])
def liste_comptes_mobiles():
    conn = get_connection()
    lignes = conn.execute('''
        SELECT u.id, u.identifiant, u.role, u.actif, c.nom_complet
        FROM utilisateurs u LEFT JOIN chauffeurs c ON c.utilisateur_id = u.id
        WHERE u.role = 'chauffeur'
        ORDER BY c.nom_complet
    ''').fetchall()
    conn.close()
    return jsonify([dict(l) for l in lignes])


@app.route('/api/chauffeurs/<int:chauffeur_id>/compte-mobile', methods=['POST'])
@authentification_requise(['moderateur'])
def creer_compte_mobile_pour_chauffeur(chauffeur_id):
    donnees = request.get_json(force=True) or {}
    identifiant = donnees.get('identifiant', '').strip()
    mot_de_passe = donnees.get('mot_de_passe', '').strip()
    if not identifiant or not mot_de_passe:
        return jsonify({'erreur': 'identifiant et mot_de_passe sont requis'}), 400

    conn = get_connection()
    chauffeur = conn.execute('SELECT * FROM chauffeurs WHERE id = ?', (chauffeur_id,)).fetchone()
    if not chauffeur:
        conn.close()
        return jsonify({'erreur': 'Chauffeur introuvable'}), 404
    if conn.execute('SELECT id FROM utilisateurs WHERE identifiant = ?', (identifiant,)).fetchone():
        conn.close()
        return jsonify({'erreur': 'Cet identifiant est déjà utilisé'}), 409

    curseur = conn.execute(
        "INSERT INTO utilisateurs (identifiant, mot_de_passe_hash, role) VALUES (?, ?, 'chauffeur')",
        (identifiant, generate_password_hash(mot_de_passe))
    )
    utilisateur_id = curseur.lastrowid
    conn.execute('UPDATE chauffeurs SET utilisateur_id = ? WHERE id = ?', (utilisateur_id, chauffeur_id))
    conn.commit()
    conn.close()
    return jsonify({'utilisateur_id': utilisateur_id}), 201


@app.route('/api/chauffeurs/me', methods=['GET'])
@authentification_requise(['chauffeur'])
def mon_profil_chauffeur():
    """Retourne fiablement la fiche du chauffeur connecté (jamais celle d'un autre)."""
    conn = get_connection()
    chauffeur = conn.execute('''
        SELECT c.*, t.immatriculation AS tracteur_immat, r.immatriculation AS remorque_immat
        FROM chauffeurs c
        LEFT JOIN tracteurs t ON t.id = c.tracteur_id
        LEFT JOIN remorques r ON r.id = c.remorque_id
        WHERE c.utilisateur_id = ?
    ''', (g.user['utilisateur_id'],)).fetchone()
    conn.close()
    if not chauffeur:
        return jsonify({'erreur': 'Fiche chauffeur introuvable pour ce compte'}), 404
    return jsonify(dict(chauffeur))


@app.route('/api/me', methods=['GET'])
@authentification_requise()
def mon_profil():
    """Retourne le profil de l'utilisateur connecté, quel que soit son rôle."""
    conn = get_connection()
    if g.user['role'] == 'chauffeur':
        chauffeur = conn.execute('''
            SELECT c.*, t.immatriculation AS tracteur_immat, r.immatriculation AS remorque_immat
            FROM chauffeurs c
            LEFT JOIN tracteurs t ON t.id = c.tracteur_id
            LEFT JOIN remorques r ON r.id = c.remorque_id
            WHERE c.utilisateur_id = ?
        ''', (g.user['utilisateur_id'],)).fetchone()
        conn.close()
        if not chauffeur:
            return jsonify({'erreur': 'Fiche chauffeur introuvable pour ce compte'}), 404
        return jsonify({'role': 'chauffeur', **dict(chauffeur)})
    else:
        utilisateur = conn.execute('SELECT id, identifiant, role FROM utilisateurs WHERE id = ?', (g.user['utilisateur_id'],)).fetchone()
        conn.close()
        return jsonify({'role': 'moderateur', **dict(utilisateur)})


# ============================================================
# SANTÉ DE L'API
# ============================================================

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'statut': 'ok', 'service': 'Transports A.Blondel API'})


# Initialise la base au chargement du module, pour que ça fonctionne aussi
# quand l'app est lancée par gunicorn (production) et pas seulement par
# `python3 app.py` (local) — gunicorn n'exécute jamais le bloc __main__ ci-dessous.
init_db()
seed_admin()

# ============================================================
# GESTION : charges manuelles, paramètres de TVA, compte de résultat
# ============================================================

from decimal import Decimal, ROUND_HALF_UP

CENT = Decimal('0.01')

CATEGORIES_CHARGES = [
    'Assurances', 'Crédits et leasing', 'Entretien et réparations',
    'Pneumatiques', 'Péages', 'Loyers et charges locatives', 'Honoraires (comptable...)',
    'Impôts et taxes', 'Frais bancaires', 'Abonnements (téléphone, logiciels...)', 'Fournitures et divers', 'Autres charges'
]
PARAMETRES_DEFAUT = {'tva_carburant': '20', 'tva_achats_pro': '20'}


def _dec(valeur):
    return Decimal(str(valeur if valeur is not None else 0))


def _ht_tva(ttc, taux):
    """Découpe un montant TTC en HT + TVA, arrondi au centime (la TVA = TTC - HT, donc la somme est exacte)."""
    ttc = _dec(ttc).quantize(CENT, ROUND_HALF_UP)
    ht = (ttc / (Decimal('1') + _dec(taux) / Decimal('100'))).quantize(CENT, ROUND_HALF_UP)
    return ttc, ht, ttc - ht


def _lire_parametres(conn):
    p = dict(PARAMETRES_DEFAUT)
    for l in conn.execute('SELECT cle, valeur FROM parametres_gestion').fetchall():
        p[l['cle']] = l['valeur']
    return p


@app.route('/api/gestion/parametres', methods=['GET'])
@authentification_requise(['moderateur', 'comptable'])
def lire_parametres_gestion():
    conn = get_connection()
    p = _lire_parametres(conn)
    conn.close()
    return jsonify({'parametres': p, 'categories': CATEGORIES_CHARGES})


@app.route('/api/gestion/parametres', methods=['PUT'])
@authentification_requise(['moderateur'])
def enregistrer_parametres_gestion():
    donnees = request.get_json(force=True) or {}
    conn = get_connection()
    for cle in PARAMETRES_DEFAUT:
        if cle in donnees:
            try:
                valeur = float(donnees[cle])
            except (TypeError, ValueError):
                conn.close()
                return jsonify({'erreur': 'Taux de TVA invalide'}), 400
            if valeur < 0 or valeur > 100:
                conn.close()
                return jsonify({'erreur': 'Le taux de TVA doit être entre 0 et 100'}), 400
            conn.execute(
                'INSERT INTO parametres_gestion (cle, valeur) VALUES (?, ?) '
                'ON CONFLICT(cle) DO UPDATE SET valeur = excluded.valeur', (cle, str(valeur)))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/gestion/charges', methods=['GET'])
@authentification_requise(['moderateur', 'comptable'])
def liste_charges_manuelles():
    annee = request.args.get('annee')
    conn = get_connection()
    if annee:
        lignes = conn.execute('SELECT * FROM charges_manuelles WHERE date_charge LIKE ? ORDER BY date_charge DESC, id DESC',
                              (f'{annee}%',)).fetchall()
    else:
        lignes = conn.execute('SELECT * FROM charges_manuelles ORDER BY date_charge DESC, id DESC').fetchall()
    conn.close()
    return jsonify([dict(l) for l in lignes])


@app.route('/api/gestion/charges', methods=['POST'])
@authentification_requise(['moderateur'])
def creer_charge_manuelle():
    d = request.get_json(force=True) or {}
    try:
        montant = float(d.get('montant_ttc'))
        taux = float(d.get('taux_tva', 20))
    except (TypeError, ValueError):
        return jsonify({'erreur': 'Montant ou taux de TVA invalide'}), 400
    if not d.get('date_charge') or not (d.get('libelle') or '').strip() or not d.get('categorie'):
        return jsonify({'erreur': 'Date, libellé et catégorie sont requis'}), 400
    if taux < 0 or taux > 100:
        return jsonify({'erreur': 'Le taux de TVA doit être entre 0 et 100'}), 400
    conn = get_connection()
    c = conn.execute(
        'INSERT INTO charges_manuelles (date_charge, libelle, categorie, montant_ttc, taux_tva) VALUES (?, ?, ?, ?, ?)',
        (d['date_charge'], d['libelle'].strip(), d['categorie'], montant, taux))
    conn.commit()
    nouvel_id = c.lastrowid
    conn.close()
    return jsonify({'id': nouvel_id}), 201


@app.route('/api/gestion/charges/<int:charge_id>', methods=['DELETE'])
@authentification_requise(['moderateur'])
def supprimer_charge_manuelle(charge_id):
    conn = get_connection()
    conn.execute('DELETE FROM charges_manuelles WHERE id = ?', (charge_id,))
    conn.commit()
    conn.close()
    return '', 204


PREFIXE_EXCEPTIONNEL = 'Exceptionnel — '
PAS_FREQUENCE = {'mensuelle': 1, 'trimestrielle': 3, 'annuelle': 12}


def _echeances_charge_fixe(charge, annee):
    """Mois (0-11) de l'année où une charge fixe est payée : à partir de sa date de début, tous les
    1, 3 ou 12 mois, jusqu'à son éventuelle date de fin."""
    pas = PAS_FREQUENCE.get(charge['frequence'], 1)
    try:
        debut_a, debut_m = int(charge['date_debut'][:4]), int(charge['date_debut'][5:7]) - 1
    except (TypeError, ValueError):
        return []
    mois_ok = []
    for m in range(12):
        ecart = (int(annee) * 12 + m) - (debut_a * 12 + debut_m)
        if ecart < 0 or ecart % pas != 0:
            continue
        if charge['date_fin'] and f'{annee}-{m + 1:02d}' > charge['date_fin'][:7]:
            continue
        mois_ok.append(m)
    return mois_ok


def _lire_donnees_charge_fixe(d):
    """Valide et normalise les champs d'une charge fixe ; renvoie (valeurs, erreur)."""
    try:
        montant = float(d.get('montant_ttc'))
        taux = float(d.get('taux_tva', 20))
    except (TypeError, ValueError):
        return None, 'Montant ou taux de TVA invalide'
    libelle = (d.get('libelle') or '').strip()
    if not libelle or not d.get('categorie') or not d.get('date_debut'):
        return None, 'Libellé, catégorie et date de début sont requis'
    if montant < 0 or taux < 0 or taux > 100:
        return None, 'Montant ou taux de TVA invalide'
    frequence = d.get('frequence') or 'mensuelle'
    if frequence not in PAS_FREQUENCE:
        return None, 'Fréquence invalide'
    date_fin = d.get('date_fin') or None
    if date_fin and date_fin < d['date_debut']:
        return None, 'La date de fin est avant la date de début'
    return (libelle, d['categorie'], round(montant, 2), taux, frequence, d['date_debut'], date_fin), None


@app.route('/api/gestion/charges-fixes', methods=['GET'])
@authentification_requise(['moderateur', 'comptable'])
def liste_charges_fixes():
    conn = get_connection()
    lignes = conn.execute('SELECT * FROM charges_fixes ORDER BY categorie, libelle').fetchall()
    conn.close()
    return jsonify([dict(l) for l in lignes])


@app.route('/api/gestion/charges-fixes', methods=['POST'])
@authentification_requise(['moderateur'])
def creer_charge_fixe():
    valeurs, erreur = _lire_donnees_charge_fixe(request.get_json(force=True) or {})
    if erreur:
        return jsonify({'erreur': erreur}), 400
    conn = get_connection()
    c = conn.execute('INSERT INTO charges_fixes (libelle, categorie, montant_ttc, taux_tva, frequence, date_debut, date_fin) '
                     'VALUES (?, ?, ?, ?, ?, ?, ?)', valeurs)
    conn.commit()
    nouvel_id = c.lastrowid
    conn.close()
    return jsonify({'id': nouvel_id}), 201


@app.route('/api/gestion/charges-fixes/<int:charge_id>', methods=['PUT'])
@authentification_requise(['moderateur'])
def modifier_charge_fixe(charge_id):
    valeurs, erreur = _lire_donnees_charge_fixe(request.get_json(force=True) or {})
    if erreur:
        return jsonify({'erreur': erreur}), 400
    conn = get_connection()
    conn.execute('UPDATE charges_fixes SET libelle = ?, categorie = ?, montant_ttc = ?, taux_tva = ?, frequence = ?, '
                 'date_debut = ?, date_fin = ? WHERE id = ?', (*valeurs, charge_id))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/gestion/charges-fixes/<int:charge_id>/changer-montant', methods=['POST'])
@authentification_requise(['moderateur'])
def changer_montant_charge_fixe(charge_id):
    """Change le montant d'une charge fixe À PARTIR d'un mois donné, sans toucher à l'historique :
    l'ancienne charge se termine la veille, une nouvelle commence avec le nouveau montant."""
    from datetime import date, timedelta
    d = request.get_json(force=True) or {}
    try:
        montant = round(float(d.get('montant_ttc')), 2)
        if montant < 0:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({'erreur': 'Montant invalide'}), 400
    date_effet = (d.get('date_effet') or '')[:7]
    if len(date_effet) != 7:
        return jsonify({'erreur': "Le mois d'effet est requis"}), 400
    date_effet += '-01'   # toujours le 1er du mois : un mois n'est jamais compté deux fois

    conn = get_connection()
    ancienne = conn.execute('SELECT * FROM charges_fixes WHERE id = ?', (charge_id,)).fetchone()
    if not ancienne:
        conn.close()
        return jsonify({'erreur': 'Charge fixe introuvable'}), 404
    try:
        taux = float(d['taux_tva']) if d.get('taux_tva') not in (None, '') else ancienne['taux_tva']
    except (TypeError, ValueError):
        conn.close()
        return jsonify({'erreur': 'Taux de TVA invalide'}), 400
    if ancienne['date_fin'] and date_effet[:7] > ancienne['date_fin'][:7]:
        conn.close()
        return jsonify({'erreur': "Cette charge est déjà terminée à cette date."}), 400

    if date_effet[:7] <= ancienne['date_debut'][:7]:
        # Le changement a effet dès le début : aucun historique à préserver, on met simplement à jour
        conn.execute('UPDATE charges_fixes SET montant_ttc = ?, taux_tva = ? WHERE id = ?', (montant, taux, charge_id))
        nouvel_id = charge_id
    else:
        veille = (date.fromisoformat(date_effet) - timedelta(days=1)).isoformat()
        conn.execute('UPDATE charges_fixes SET date_fin = ? WHERE id = ?', (veille, charge_id))
        c = conn.execute(
            'INSERT INTO charges_fixes (libelle, categorie, montant_ttc, taux_tva, frequence, date_debut, date_fin) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (ancienne['libelle'], ancienne['categorie'], montant, taux, ancienne['frequence'], date_effet, ancienne['date_fin']))
        nouvel_id = c.lastrowid
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'id': nouvel_id})


@app.route('/api/gestion/charges-fixes/<int:charge_id>', methods=['DELETE'])
@authentification_requise(['moderateur'])
def supprimer_charge_fixe(charge_id):
    conn = get_connection()
    conn.execute('DELETE FROM charges_fixes WHERE id = ?', (charge_id,))
    conn.commit()
    conn.close()
    return '', 204


@app.route('/api/gestion/produits-exceptionnels', methods=['GET'])
@authentification_requise(['moderateur', 'comptable'])
def liste_produits_exceptionnels():
    annee = request.args.get('annee')
    conn = get_connection()
    if annee:
        lignes = conn.execute('SELECT * FROM produits_exceptionnels WHERE date_produit LIKE ? ORDER BY date_produit DESC, id DESC',
                              (f'{annee}%',)).fetchall()
    else:
        lignes = conn.execute('SELECT * FROM produits_exceptionnels ORDER BY date_produit DESC, id DESC').fetchall()
    conn.close()
    return jsonify([dict(l) for l in lignes])


@app.route('/api/gestion/produits-exceptionnels', methods=['POST'])
@authentification_requise(['moderateur'])
def creer_produit_exceptionnel():
    d = request.get_json(force=True) or {}
    try:
        montant = float(d.get('montant_ttc'))
        taux = float(d.get('taux_tva', 20))
    except (TypeError, ValueError):
        return jsonify({'erreur': 'Montant ou taux de TVA invalide'}), 400
    if not d.get('date_produit') or not (d.get('libelle') or '').strip():
        return jsonify({'erreur': 'Date et libellé sont requis'}), 400
    if taux < 0 or taux > 100:
        return jsonify({'erreur': 'Le taux de TVA doit être entre 0 et 100'}), 400
    conn = get_connection()
    c = conn.execute('INSERT INTO produits_exceptionnels (date_produit, libelle, montant_ttc, taux_tva) VALUES (?, ?, ?, ?)',
                     (d['date_produit'], d['libelle'].strip(), round(montant, 2), taux))
    conn.commit()
    nouvel_id = c.lastrowid
    conn.close()
    return jsonify({'id': nouvel_id}), 201


@app.route('/api/gestion/produits-exceptionnels/<int:produit_id>', methods=['DELETE'])
@authentification_requise(['moderateur'])
def supprimer_produit_exceptionnel(produit_id):
    conn = get_connection()
    conn.execute('DELETE FROM produits_exceptionnels WHERE id = ?', (produit_id,))
    conn.commit()
    conn.close()
    return '', 204


@app.route('/api/gestion/salaires', methods=['GET'])
@authentification_requise(['moderateur', 'comptable'])
def liste_salaires():
    """Pour un mois (YYYY-MM) : une ligne par chauffeur (même sans saisie), + le suivi de la DSN du mois."""
    mois = request.args.get('mois')
    if not mois or len(mois) != 7:
        return jsonify({'erreur': 'Le paramètre mois (YYYY-MM) est requis'}), 400
    conn = get_connection()
    chauffeurs = conn.execute('SELECT id, nom_complet FROM chauffeurs ORDER BY nom_complet').fetchall()
    saisies = {l['chauffeur_id']: dict(l) for l in conn.execute('SELECT * FROM salaires WHERE mois = ?', (mois,)).fetchall()}
    lignes = []
    for c in chauffeurs:
        s = saisies.pop(c['id'], None)
        lignes.append({
            'chauffeur_id': c['id'], 'chauffeur_nom': c['nom_complet'],
            'brut': s['brut'] if s else None, 'charges_patronales': s['charges_patronales'] if s else None,
            'net_paye': s['net_paye'] if s else None, 'saisi': bool(s)
        })
    for s in saisies.values():   # chauffeurs supprimés depuis, dont l'historique est conservé
        lignes.append({
            'chauffeur_id': s['chauffeur_id'], 'chauffeur_nom': (s['chauffeur_nom'] or 'Ancien chauffeur') + ' (supprimé)',
            'brut': s['brut'], 'charges_patronales': s['charges_patronales'], 'net_paye': s['net_paye'], 'saisi': True
        })
    dsn = conn.execute('SELECT * FROM dsn_mensuelles WHERE mois = ?', (mois,)).fetchone()
    conn.close()
    return jsonify({'mois': mois, 'lignes': lignes, 'dsn': dict(dsn) if dsn else {'mois': mois, 'date_depot': None, 'montant': None, 'note': None}})


@app.route('/api/gestion/salaires', methods=['PUT'])
@authentification_requise(['moderateur'])
def enregistrer_salaire():
    """Salaire NET du mois d'un chauffeur (indemnités de route incluses). Vide ou 0 = efface la saisie."""
    d = request.get_json(force=True) or {}
    mois = d.get('mois')
    chauffeur_id = d.get('chauffeur_id')
    if not mois or len(mois) != 7 or not chauffeur_id:
        return jsonify({'erreur': 'mois et chauffeur_id sont requis'}), 400
    try:
        v = d.get('net_paye')
        net = None if v is None or v == '' else round(float(v), 2)
        if net is not None and net < 0:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({'erreur': 'Montant invalide'}), 400

    conn = get_connection()
    chauffeur = conn.execute('SELECT nom_complet FROM chauffeurs WHERE id = ?', (chauffeur_id,)).fetchone()
    if not chauffeur:
        conn.close()
        return jsonify({'erreur': 'Chauffeur introuvable'}), 404
    if not net:
        conn.execute('DELETE FROM salaires WHERE chauffeur_id = ? AND mois = ?', (chauffeur_id, mois))
    else:
        conn.execute(
            'INSERT INTO salaires (chauffeur_id, chauffeur_nom, mois, brut, charges_patronales, net_paye) VALUES (?, ?, ?, 0, 0, ?) '
            'ON CONFLICT(chauffeur_id, mois) DO UPDATE SET net_paye = excluded.net_paye, chauffeur_nom = excluded.chauffeur_nom',
            (chauffeur_id, chauffeur['nom_complet'], mois, net))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/gestion/dsn', methods=['PUT'])
@authentification_requise(['moderateur'])
def enregistrer_dsn():
    d = request.get_json(force=True) or {}
    mois = d.get('mois')
    if not mois or len(mois) != 7:
        return jsonify({'erreur': 'Le mois (YYYY-MM) est requis'}), 400
    conn = get_connection()
    try:
        v = d.get('montant')
        montant = None if v is None or v == '' else round(float(v), 2)
        if montant is not None and montant < 0:
            raise ValueError
    except (TypeError, ValueError):
        conn.close()
        return jsonify({'erreur': 'Montant invalide'}), 400
    conn.execute(
        'INSERT INTO dsn_mensuelles (mois, date_depot, montant, note) VALUES (?, ?, ?, ?) '
        'ON CONFLICT(mois) DO UPDATE SET date_depot = excluded.date_depot, montant = excluded.montant, note = excluded.note',
        (mois, d.get('date_depot') or None, montant, d.get('note') or None))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/gestion/compte-resultat', methods=['GET'])
@authentification_requise(['moderateur', 'comptable'])
def compte_de_resultat():
    """Exercice = année civile. Tout est calculé ligne par ligne au centime (HT arrondi par ligne,
    TVA = TTC - HT), puis additionné : les totaux sont donc exacts, sans écart d'arrondi."""
    annee = request.args.get('annee') or aujourdhui_fr()[:4]
    prefixe = f'{annee}-'
    conn = get_connection()
    params = _lire_parametres(conn)

    def vide():
        return {'ttc': [Decimal('0')] * 12, 'ht': [Decimal('0')] * 12, 'tva': [Decimal('0')] * 12}

    def ajouter(bloc, date_iso, ttc, taux):
        try:
            m = int(date_iso[5:7]) - 1
        except (TypeError, ValueError):
            return
        if not 0 <= m < 12:
            return
        t, h, v = _ht_tva(ttc, taux)
        bloc['ttc'][m] += t
        bloc['ht'][m] += h
        bloc['tva'][m] += v

    def ajouter_ht(bloc, date_iso, ht, taux):
        # Montant saisi en HT : TVA = HT x taux (arrondie au centime), TTC = HT + TVA
        try:
            m = int(date_iso[5:7]) - 1
        except (TypeError, ValueError):
            return
        if not 0 <= m < 12:
            return
        h = _dec(ht).quantize(CENT, ROUND_HALF_UP)
        v = (h * _dec(taux) / Decimal('100')).quantize(CENT, ROUND_HALF_UP)
        bloc['ht'][m] += h
        bloc['tva'][m] += v
        bloc['ttc'][m] += h + v

    # Produits : lignes de facturation saisies en HT (mois = date de la mission)
    # + factures globales (mois = mois facturé)
    ventes = vide()
    sans_montant = 0
    nb_ventes = 0
    for l in conn.execute('SELECT * FROM facturation').fetchall():
        date_ref = l['date_mission']   # le produit est rattaché au mois de la mission
        if not date_ref or not date_ref.startswith(prefixe):
            continue
        if l['facture_groupee_id']:
            continue   # le montant est porté par la facture globale (ajoutée plus bas)
        if l['montant_ht'] is None:
            sans_montant += 1
            continue
        nb_ventes += 1
        ajouter_ht(ventes, date_ref, l['montant_ht'], l['taux_tva'])
    for f in conn.execute('SELECT * FROM factures_groupees WHERE mois LIKE ?', (f'{prefixe}%',)).fetchall():
        nb_ventes += 1
        ajouter_ht(ventes, f['mois'] + '-01', f['montant_ht'], f['taux_tva'])

    # Produits exceptionnels (hors missions)
    produits_exc = vide()
    for l in conn.execute('SELECT * FROM produits_exceptionnels WHERE date_produit LIKE ?', (f'{prefixe}%',)).fetchall():
        ajouter(produits_exc, l['date_produit'], l['montant_ttc'], l['taux_tva'])

    # Charges reprises automatiquement
    carburant = vide()
    for l in conn.execute('SELECT date_plein, prix_total FROM pleins_carburant WHERE date_plein LIKE ? AND prix_total IS NOT NULL',
                          (f'{prefixe}%',)).fetchall():
        ajouter(carburant, l['date_plein'], l['prix_total'], params['tva_carburant'])

    achats = vide()
    for l in conn.execute("SELECT date_achat, montant, taux_tva FROM achats WHERE type = 'pro' AND date_achat LIKE ?",
                          (f'{prefixe}%',)).fetchall():
        taux_achat = l['taux_tva'] if l['taux_tva'] is not None else params['tva_achats_pro']
        ajouter(achats, l['date_achat'], l['montant'], taux_achat)

    # Salaires nets + montant de la DSN : pas de TVA (HT = TTC). Les indemnités de route sont incluses dans le net.
    salaires_nets = vide()
    cotisations = vide()
    for l in conn.execute('SELECT * FROM salaires WHERE mois LIKE ? AND net_paye IS NOT NULL', (f'{prefixe}%',)).fetchall():
        ajouter(salaires_nets, l['mois'] + '-01', l['net_paye'], 0)
    for l in conn.execute('SELECT * FROM dsn_mensuelles WHERE mois LIKE ? AND montant IS NOT NULL', (f'{prefixe}%',)).fetchall():
        ajouter(cotisations, l['mois'] + '-01', l['montant'], 0)

    charges = {
        'Salaires nets des chauffeurs (indemnités incluses)': salaires_nets,
        'Cotisations sociales et prélèvements (DSN)': cotisations,
        'Carburant (pleins enregistrés)': carburant,
        'Achats professionnels des chauffeurs': achats,
    }
    # Charges exceptionnelles (ponctuelles) : présentées à part, sous le préfixe « Exceptionnel — »
    for l in conn.execute('SELECT * FROM charges_manuelles WHERE date_charge LIKE ?', (f'{prefixe}%',)).fetchall():
        bloc = charges.setdefault(PREFIXE_EXCEPTIONNEL + l['categorie'], vide())
        ajouter(bloc, l['date_charge'], l['montant_ttc'], l['taux_tva'])
    # Charges fixes récurrentes : une écriture à chaque échéance de l'année
    for l in conn.execute('SELECT * FROM charges_fixes').fetchall():
        for m in _echeances_charge_fixe(l, annee):
            bloc = charges.setdefault(l['categorie'], vide())
            ajouter(bloc, f'{annee}-{m + 1:02d}-01', l['montant_ttc'], l['taux_tva'])
    conn.close()

    def somme(liste):
        return sum(liste, Decimal('0'))

    def exporter(bloc):
        sortie = {c: [float(x) for x in bloc[c]] for c in ('ttc', 'ht', 'tva')}
        sortie.update({'total_ttc': float(somme(bloc['ttc'])), 'total_ht': float(somme(bloc['ht'])),
                       'total_tva': float(somme(bloc['tva']))})
        return sortie

    charges_ht_mois = [somme(b['ht'][m] for b in charges.values()) for m in range(12)]
    charges_ttc_mois = [somme(b['ttc'][m] for b in charges.values()) for m in range(12)]
    charges_tva_mois = [somme(b['tva'][m] for b in charges.values()) for m in range(12)]
    # Total des produits = ventes de transport + produits exceptionnels
    produits = {c: [ventes[c][m] + produits_exc[c][m] for m in range(12)] for c in ('ttc', 'ht', 'tva')}
    produits_ht = somme(produits['ht']); charges_ht = somme(charges_ht_mois)
    produits_ttc = somme(produits['ttc']); charges_ttc = somme(charges_ttc_mois)
    tva_collectee = somme(produits['tva']); tva_deductible = somme(charges_tva_mois)

    return jsonify({
        'annee': annee,
        'produits': exporter(produits),
        'ventes': exporter(ventes),
        'produits_exceptionnels': exporter(produits_exc),
        'nb_lignes_facturees': nb_ventes,
        'nb_lignes_sans_montant': sans_montant,
        'charges': {nom: exporter(b) for nom, b in charges.items()},
        'charges_totales': {
            'ht': [float(x) for x in charges_ht_mois], 'ttc': [float(x) for x in charges_ttc_mois],
            'tva': [float(x) for x in charges_tva_mois],
            'total_ht': float(charges_ht), 'total_ttc': float(charges_ttc), 'total_tva': float(tva_deductible)
        },
        'resultat_mensuel_ht': [float(produits['ht'][m] - charges_ht_mois[m]) for m in range(12)],
        'resultat_mensuel_ttc': [float(produits['ttc'][m] - charges_ttc_mois[m]) for m in range(12)],
        'resultat_ht': float(produits_ht - charges_ht),
        'resultat_ttc': float(produits_ttc - charges_ttc),
        'tva_collectee': float(tva_collectee),
        'tva_deductible': float(tva_deductible),
        'tva_a_payer': float(tva_collectee - tva_deductible),
        'parametres': params,
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    debug = os.environ.get('FLASK_DEBUG', 'true').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
