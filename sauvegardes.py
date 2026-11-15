"""Sauvegardes de la base de données (SQLite).

- Une copie automatique par jour (type « auto »), gardée 14 jours.
- Une copie à chaque démarrage du serveur, donc avant toute mise à jour/migration (type « demarrage »), les 5 dernières gardées.
- Des copies manuelles depuis l'application (type « manuelle »), les 10 dernières gardées.
Les copies sont faites avec l'API de sauvegarde de SQLite : elles sont cohérentes même pendant que l'application tourne.
"""
import os
import re
import sqlite3
import threading
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from database import DB_PATH

FUSEAU = ZoneInfo('Europe/Paris')
DOSSIER = os.path.join(os.path.dirname(DB_PATH), 'sauvegardes')
GARDER = {'auto': 14, 'demarrage': 5, 'manuelle': 10}
MOTIF = re.compile(r'^transports_blondel_(\d{4}-\d{2}-\d{2})_(\d{2})h(\d{2})_(auto|demarrage|manuelle)\.db$')


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
