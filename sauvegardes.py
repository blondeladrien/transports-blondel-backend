"""Sauvegardes de la base de données (SQLite).

- Une copie automatique par jour (type « auto »), gardée 14 jours.
- Une copie à chaque démarrage du serveur, donc avant toute mise à jour/migration (type « demarrage »), les 5 dernières gardées.
- Des copies manuelles depuis l'application (type « manuelle »), les 10 dernières gardées.
Les copies sont faites avec l'API de sauvegarde de SQLite : elles sont cohérentes même pendant que l'application tourne.
"""
import os
import re
import shutil
import sqlite3
import threading
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from database import DB_PATH

FUSEAU = ZoneInfo('Europe/Paris')
DOSSIER = os.path.join(os.path.dirname(DB_PATH), 'sauvegardes')
GARDER = {'auto': 14, 'demarrage': 5, 'manuelle': 10, 'restauration': 5}
MOTIF = re.compile(r'^transports_blondel_(\d{4}-\d{2}-\d{2})_(\d{2})h(\d{2})_(auto|demarrage|manuelle|restauration)\.db$')


def _copier_base(destination):
    """Copie cohérente de la base vers `destination`, puis contrôle d'intégrité. Lève une erreur si la copie est abîmée."""
    source = sqlite3.connect(DB_PATH)
    cible = sqlite3.connect(destination)
    try:
        source.backup(cible)
    finally:
        cible.close()
        source.close()
    verif = sqlite3.connect(destination)
    try:
        ok = verif.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    finally:
        verif.close()
    if not ok:
        os.remove(destination)
        raise RuntimeError("La copie de sauvegarde est corrompue (contrôle d'intégrité échoué)")


def creer_sauvegarde(type_='manuelle'):
    """Crée une sauvegarde dans le dossier dédié et renvoie son nom (None s'il n'y a pas encore de base)."""
    if not os.path.exists(DB_PATH):
        return None
    os.makedirs(DOSSIER, exist_ok=True)
    # Garde-fou : on ne remplit jamais le disque. Il faut au moins 50 Mo + 3 fois la taille de la base de libres.
    if shutil.disk_usage(DOSSIER).free < 50 * 1024 * 1024 + 3 * os.path.getsize(DB_PATH):
        nettoyer()
        if shutil.disk_usage(DOSSIER).free < 50 * 1024 * 1024 + 3 * os.path.getsize(DB_PATH):
            raise RuntimeError("Espace disque insuffisant pour une sauvegarde")
    nom = f"transports_blondel_{datetime.now(FUSEAU):%Y-%m-%d_%Hh%M}_{type_}.db"
    final = os.path.join(DOSSIER, nom)
    temporaire = f'{final}.{os.getpid()}.tmp'
    _copier_base(temporaire)
    os.replace(temporaire, final)
    nettoyer()
    return nom


def copie_temporaire(chemin_temporaire):
    """Copie fraîche de la base dans un fichier temporaire (pour le téléchargement direct)."""
    _copier_base(chemin_temporaire)


def lister():
    """Sauvegardes présentes, de la plus récente à la plus ancienne."""
    if not os.path.isdir(DOSSIER):
        return []
    resultat = []
    for nom in os.listdir(DOSSIER):
        m = MOTIF.match(nom)
        if not m:
            continue
        resultat.append({
            'nom': nom, 'date': m.group(1), 'heure': f'{m.group(2)}:{m.group(3)}', 'type': m.group(4),
            'taille': os.path.getsize(os.path.join(DOSSIER, nom)),
        })
    return sorted(resultat, key=lambda s: (s['date'], s['heure'], s['nom']), reverse=True)


def chemin_sauvegarde(nom):
    """Chemin sûr d'une sauvegarde existante, ou None (le nom doit correspondre exactement au format attendu)."""
    if not MOTIF.match(nom or ''):
        return None
    chemin = os.path.join(DOSSIER, nom)
    return chemin if os.path.isfile(chemin) else None


def nettoyer():
    """Ne garde que les N plus récentes de chaque type et supprime les fichiers temporaires oubliés."""
    existantes = lister()
    for type_, limite in GARDER.items():
        for ancienne in [s for s in existantes if s['type'] == type_][limite:]:
            try:
                os.remove(os.path.join(DOSSIER, ancienne['nom']))
            except OSError:
                pass
    if os.path.isdir(DOSSIER):
        for nom in os.listdir(DOSSIER):
            chemin = os.path.join(DOSSIER, nom)
            if nom.endswith('.tmp') and time.time() - os.path.getmtime(chemin) > 3600:
                try:
                    os.remove(chemin)
                except OSError:
                    pass


def _boucle_quotidienne():
    while True:
        try:
            maintenant = datetime.now(FUSEAU)
            auto = [s for s in lister() if s['type'] == 'auto']
            deja_aujourdhui = any(s['date'] == maintenant.date().isoformat() for s in auto)
            # Une copie par jour, de préférence après 3 h du matin (heure française), ou tout de suite s'il n'en existe aucune
            if not deja_aujourdhui and (maintenant.hour >= 3 or not auto):
                creer_sauvegarde('auto')
        except Exception as erreur:  # une sauvegarde ratée ne doit jamais faire tomber l'application
            print(f'[sauvegarde automatique] échec : {erreur}', flush=True)
        time.sleep(3600)


def demarrer_sauvegardes_automatiques():
    threading.Thread(target=_boucle_quotidienne, daemon=True, name='sauvegardes-auto').start()


# ============================================================
# RÉCUPÉRATION D'UN CHAUFFEUR SUPPRIMÉ PAR ERREUR
# On ne restaure PAS toute la base (on perdrait tout ce qui a été saisi depuis la copie) :
# on recopie uniquement la fiche du chauffeur et ses données depuis une sauvegarde.
# ============================================================
TABLES_CHAUFFEUR = ['documents_chauffeurs', 'missions', 'declarations_journee', 'indemnites', 'achats', 'facturation']


def chauffeurs_supprimes():
    """Chauffeurs présents dans une sauvegarde mais absents de la base actuelle (le plus récent exemplaire de chacun)."""
    from database import get_connection
    conn = get_connection()
    actuels = {r['id'] for r in conn.execute('SELECT id FROM chauffeurs')}
    conn.close()
    trouves = {}
    for s in lister():  # de la plus récente à la plus ancienne
        chemin = os.path.join(DOSSIER, s['nom'])
        try:
            src = sqlite3.connect(f'file:{chemin}?mode=ro', uri=True)
            for cid, nom in src.execute('SELECT id, nom_complet FROM chauffeurs'):
                if cid in actuels or cid in trouves:
                    continue
                nb_m = src.execute('SELECT COUNT(*) FROM missions WHERE chauffeur_id=?', (cid,)).fetchone()[0]
                nb_f = src.execute('SELECT COUNT(*) FROM facturation WHERE chauffeur_id=?', (cid,)).fetchone()[0]
                trouves[cid] = {'id': cid, 'nom': nom, 'sauvegarde': s['nom'], 'date': s['date'], 'heure': s['heure'],
                                'missions': nb_m, 'factures': nb_f}
            src.close()
        except sqlite3.Error:
            continue
    return sorted(trouves.values(), key=lambda c: c['nom'].lower())


def restaurer_chauffeur(nom_sauvegarde, chauffeur_id):
    """Recopie la fiche d'un chauffeur et toutes ses données depuis une sauvegarde. Renvoie un résumé."""
    from database import get_connection
    chemin = chemin_sauvegarde(nom_sauvegarde)
    if not chemin:
        raise ValueError('Sauvegarde introuvable')
    creer_sauvegarde('manuelle')  # filet de sécurité : on peut annuler en restaurant cette copie
    conn = get_connection()
    try:
        if conn.execute('SELECT 1 FROM chauffeurs WHERE id=?', (chauffeur_id,)).fetchone():
            raise ValueError('Ce chauffeur existe déjà')
        conn.execute('ATTACH DATABASE ? AS sauv', (chemin,))
        fiche = conn.execute('SELECT * FROM sauv.chauffeurs WHERE id=?', (chauffeur_id,)).fetchone()
        if not fiche:
            raise ValueError("Ce chauffeur n'est pas dans cette sauvegarde")
        resume = {'chauffeur': fiche['nom_complet']}

        def colonnes(table):
            live = [r['name'] for r in conn.execute(f'PRAGMA main.table_info({table})')]
            sauv = {r['name'] for r in conn.execute(f'PRAGMA sauv.table_info({table})')}
            return [c for c in live if c in sauv]

        # Compte mobile : on le recrée seulement si son identifiant est libre
        uid = fiche['utilisateur_id']
        compte_ok = False
        if uid:
            u = conn.execute('SELECT * FROM sauv.utilisateurs WHERE id=?', (uid,)).fetchone()
            if u and not conn.execute('SELECT 1 FROM utilisateurs WHERE id=? OR identifiant=?', (uid, u['identifiant'])).fetchone():
                cols = ','.join(colonnes('utilisateurs'))
                conn.execute(f'INSERT INTO utilisateurs ({cols}) SELECT {cols} FROM sauv.utilisateurs WHERE id=?', (uid,))
                compte_ok = True
        resume['compte_mobile'] = compte_ok

        # Fiche chauffeur (liens vers véhicules/compte conservés seulement s'ils existent encore)
        cols = colonnes('chauffeurs')
        valeurs = []
        for c in cols:
            v = fiche[c]
            if c == 'utilisateur_id' and not compte_ok:
                v = None
            elif c in ('tracteur_id', 'tracteur_attitre_id') and v is not None and not conn.execute('SELECT 1 FROM tracteurs WHERE id=?', (v,)).fetchone():
                v = None
            elif c in ('remorque_id', 'remorque_attitree_id') and v is not None and not conn.execute('SELECT 1 FROM remorques WHERE id=?', (v,)).fetchone():
                v = None
            valeurs.append(v)
        conn.execute(f"INSERT INTO chauffeurs ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", valeurs)

        # Missions d'abord (la facturation les référence), puis le reste
        for table in ['documents_chauffeurs', 'missions', 'declarations_journee', 'indemnites', 'achats', 'facturation']:
            cols = ','.join(colonnes(table))
            conn.execute(f'INSERT OR IGNORE INTO {table} ({cols}) SELECT {cols} FROM sauv.{table} WHERE chauffeur_id=?', (chauffeur_id,))
            resume[table] = conn.execute(f'SELECT COUNT(*) FROM main.{table} WHERE chauffeur_id=?', (chauffeur_id,)).fetchone()[0]
        # Liens à remettre en place
        conn.execute('UPDATE declarations_journee SET tracteur_id=NULL WHERE chauffeur_id=? AND tracteur_id NOT IN (SELECT id FROM tracteurs)', (chauffeur_id,))
        conn.execute('UPDATE facturation SET facture_groupee_id=NULL WHERE chauffeur_id=? AND facture_groupee_id IS NOT NULL AND facture_groupee_id NOT IN (SELECT id FROM factures_groupees)', (chauffeur_id,))
        conn.execute('UPDATE facturation SET mission_id=NULL WHERE chauffeur_id=? AND mission_id IS NOT NULL AND mission_id NOT IN (SELECT id FROM missions)', (chauffeur_id,))
        # Pleins de carburant : rattachés à nouveau au chauffeur (ils n'avaient pas été supprimés, seulement détachés)
        cur = conn.execute('UPDATE pleins_carburant SET chauffeur_id=? WHERE chauffeur_id IS NULL AND id IN (SELECT id FROM sauv.pleins_carburant WHERE chauffeur_id=?)', (chauffeur_id, chauffeur_id))
        resume['pleins_carburant'] = cur.rowcount
        conn.commit()
        return resume
    except Exception:
        conn.rollback()
        raise
    finally:
        try:
            conn.execute('DETACH DATABASE sauv')
        except sqlite3.Error:
            pass
        conn.close()


def restaurer_base(nom_sauvegarde):
    """Remet TOUTE la base dans l'état d'une sauvegarde. Une copie de l'état actuel est faite avant (type « restauration »)."""
    chemin = chemin_sauvegarde(nom_sauvegarde)
    if not chemin:
        raise ValueError('Sauvegarde introuvable')
    import tempfile
    descripteur, temporaire = tempfile.mkstemp(suffix='.db', dir=DOSSIER)
    os.close(descripteur)
    try:
        # On travaille sur une copie de la sauvegarde choisie : elle ne peut pas être écrasée pendant l'opération
        shutil.copyfile(chemin, temporaire)
        controle = sqlite3.connect(temporaire)
        try:
            if controle.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise ValueError('Cette sauvegarde est abîmée : restauration annulée')
        finally:
            controle.close()
        creer_sauvegarde('restauration')
        source = sqlite3.connect(temporaire)
        cible = sqlite3.connect(DB_PATH, timeout=30)
        try:
            source.backup(cible)
        finally:
            cible.close()
            source.close()
    finally:
        if os.path.exists(temporaire):
            os.remove(temporaire)
