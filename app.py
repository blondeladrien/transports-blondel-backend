import os
from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_connection, init_db, seed_admin
from auth import generer_token, authentification_requise

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


@app.route('/api/chauffeurs/me', methods=['GET'])
@authentification_requise(['chauffeur'])
def ma_fiche_chauffeur():
    """Renvoie la fiche du chauffeur actuellement connecté — évite toute ambiguïté
    si plusieurs chauffeurs existent (contrairement à /api/chauffeurs qui liste tout le monde)."""
    conn = get_connection()
    ligne = conn.execute('''
        SELECT c.*, t.immatriculation AS tracteur_immat, r.immatriculation AS remorque_immat
        FROM chauffeurs c
        LEFT JOIN tracteurs t ON t.id = c.tracteur_id
        LEFT JOIN remorques r ON r.id = c.remorque_id
        WHERE c.utilisateur_id = ?
    ''', (g.user['utilisateur_id'],)).fetchone()
    conn.close()
    if not ligne:
        return jsonify({'erreur': 'Aucune fiche chauffeur associée à ce compte'}), 404
    return jsonify(dict(ligne))


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
    if 'tracteur_id' in donnees:
        champs.append('tracteur_id = ?')
        valeurs.append(donnees['tracteur_id'])
    if 'remorque_id' in donnees:
        champs.append('remorque_id = ?')
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
@authentification_requise(['moderateur'])
def creer_mission():
    donnees = request.get_json(force=True) or {}
    requis = ['chauffeur_id', 'date_mission']
    if not all(donnees.get(champ) for champ in requis):
        return jsonify({'erreur': 'chauffeur_id et date_mission sont requis'}), 400

    conn = get_connection()
    curseur = conn.execute('''
        INSERT INTO missions (chauffeur_id, date_mission, heure_depart, client, adresse, chef_de_chantier)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        donnees['chauffeur_id'], donnees['date_mission'], donnees.get('heure_depart'),
        donnees.get('client'), donnees.get('adresse'), donnees.get('chef_de_chantier')
    ))
    conn.commit()
    mission_id = curseur.lastrowid
    conn.close()
    return jsonify({'id': mission_id}), 201


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
@authentification_requise(['moderateur'])
def liste_facturation():
    conn = get_connection()
    lignes = conn.execute('''
        SELECT f.*, c.nom_complet AS chauffeur_nom
        FROM facturation f JOIN chauffeurs c ON c.id = f.chauffeur_id
        ORDER BY f.date_mission DESC
    ''').fetchall()
    conn.close()
    return jsonify([dict(l) for l in lignes])


@app.route('/api/facturation/<int:ligne_id>', methods=['PATCH'])
@authentification_requise(['moderateur'])
def facturer_ligne(ligne_id):
    donnees = request.get_json(force=True) or {}
    conn = get_connection()
    conn.execute(
        'UPDATE facturation SET numero_facture = ?, date_facturation = ? WHERE id = ?',
        (donnees.get('numero_facture'), donnees.get('date_facturation'), ligne_id)
    )
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


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
    """Renvoie la déclaration du jour, et propose comme km de départ celui de la DERNIÈRE
    clôture enregistrée (peu importe le nombre de jours écoulés depuis), à condition que
    le tracteur n'ait pas changé entre-temps."""
    chauffeur = _chauffeur_id_du_token()
    if not chauffeur:
        return jsonify({'erreur': 'Fiche chauffeur introuvable'}), 404

    conn = get_connection()
    aujourdhui = request.args.get('date') or __import__('datetime').date.today().isoformat()

    existante = conn.execute(
        'SELECT * FROM declarations_journee WHERE chauffeur_id = ? AND date_jour = ?',
        (chauffeur['id'], aujourdhui)
    ).fetchone()

    km_depart_suggere = None
    if not existante or not existante['km_depart']:
        derniere = conn.execute('''
            SELECT km_arrivee, tracteur_id FROM declarations_journee
            WHERE chauffeur_id = ? AND date_jour < ? AND km_arrivee IS NOT NULL
            ORDER BY date_jour DESC LIMIT 1
        ''', (chauffeur['id'], aujourdhui)).fetchone()
        if derniere and derniere['tracteur_id'] == chauffeur['tracteur_id']:
            km_depart_suggere = derniere['km_arrivee']

    conn.close()
    return jsonify({
        'declaration': dict(existante) if existante else None,
        'km_depart_suggere': km_depart_suggere
    })


@app.route('/api/declarations/km-depart', methods=['POST'])
@authentification_requise(['chauffeur'])
def declarer_km_depart():
    chauffeur = _chauffeur_id_du_token()
    if not chauffeur:
        return jsonify({'erreur': 'Fiche chauffeur introuvable'}), 404
    donnees = request.get_json(force=True) or {}
    aujourdhui = donnees.get('date') or __import__('datetime').date.today().isoformat()

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
    aujourdhui = donnees.get('date') or __import__('datetime').date.today().isoformat()

    conn = get_connection()
    conn.execute('''
        UPDATE declarations_journee
        SET km_arrivee = ?, heure_fin_service = time('now')
        WHERE chauffeur_id = ? AND date_jour = ?
    ''', (donnees.get('km_arrivee'), chauffeur['id'], aujourdhui))
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
    aujourdhui = donnees.get('date') or __import__('datetime').date.today().isoformat()

    conn = get_connection()
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


# ============================================================
# ACHATS (pro / perso)
# ============================================================

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
    conn.close()
    return jsonify([dict(l) for l in lignes])


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
    curseur = conn.execute('''
        INSERT INTO achats (chauffeur_id, type, date_achat, description, montant)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        chauffeur['id'], donnees['type'],
        donnees.get('date_achat') or __import__('datetime').date.today().isoformat(),
        donnees.get('description'), float(donnees['montant'])
    ))
    conn.commit()
    achat_id = curseur.lastrowid
    conn.close()
    return jsonify({'id': achat_id}), 201


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
    annee = request.args.get('annee', str(__import__('datetime').date.today().year))
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
        SELECT 'mission' AS type, m.date_mission AS date, c.nom_complet AS chauffeur,
               m.client AS detail, m.statut AS info
        FROM missions m JOIN chauffeurs c ON c.id = m.chauffeur_id
    ''').fetchall()
    frais = conn.execute('''
        SELECT 'frais' AS type, i.date_jour AS date, c.nom_complet AS chauffeur,
               'Indemnités' AS detail, '' AS info
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
    champs_autorises = ['date_mission', 'heure_depart', 'client', 'adresse', 'chef_de_chantier', 'statut']
    a_modifier = {k: v for k, v in donnees.items() if k in champs_autorises}
    if not a_modifier:
        return jsonify({'erreur': 'Aucun champ valide à modifier'}), 400

    conn = get_connection()
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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    debug = os.environ.get('FLASK_DEBUG', 'true').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
