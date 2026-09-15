import sqlite3
import os

# En production, définissez la variable d'environnement DB_PATH pour pointer vers
# le disque persistant Render (ex. /var/data/transports_blondel.db) — sans cette
# variable, la base est stockée à côté du code, sur un disque effacé à chaque déploiement.
DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'transports_blondel.db'))
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), 'schema.sql')


def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def init_db():
    """Crée les tables si elles n'existent pas encore, et migre les bases déjà existantes
    (ajout de colonnes sans jamais perdre les données déjà en place)."""
    conn = get_connection()
    with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
        conn.executescript(f.read())
    conn.commit()
    _migrer_vehicule_attitre(conn)
    _migrer_note_facturation(conn)
    _migrer_documents_remorques(conn)
    conn.close()


def _migrer_documents_remorques(conn):
    """Ajoute aux remorques les mêmes colonnes de documents que les tracteurs (assurance,
    extincteur, chronotachygraphe, tachylimiteur) — absentes jusqu'ici, ce qui faisait que ces
    dates semblaient s'enregistrer dans l'interface mais disparaissaient à chaque reconnexion,
    faute d'un endroit où les sauvegarder réellement en base."""
    colonnes = {row['name'] for row in conn.execute("PRAGMA table_info(remorques)").fetchall()}
    for champ in ('date_assurance', 'date_extincteur', 'date_chronotachygraphe', 'date_tachylimiteur'):
        if champ not in colonnes:
            conn.execute(f'ALTER TABLE remorques ADD COLUMN {champ} TEXT')
    conn.commit()


def _migrer_note_facturation(conn):
    """Ajoute la colonne note à la table facturation si elle n'existe pas encore."""
    colonnes = {row['name'] for row in conn.execute("PRAGMA table_info(facturation)").fetchall()}
    if 'note' not in colonnes:
        conn.execute('ALTER TABLE facturation ADD COLUMN note TEXT')
        conn.commit()


def _migrer_vehicule_attitre(conn):
    """Ajoute les colonnes de véhicule ATTITRÉ (permanent) si elles n'existent pas encore sur
    une base déjà en production, et reprend l'attribution actuelle comme valeur de départ —
    aucun chauffeur ne perd son véhicule du jour au lendemain à cause de cette migration."""
    colonnes = {row['name'] for row in conn.execute("PRAGMA table_info(chauffeurs)").fetchall()}
    if 'tracteur_attitre_id' not in colonnes:
        conn.execute('ALTER TABLE chauffeurs ADD COLUMN tracteur_attitre_id INTEGER REFERENCES tracteurs(id) ON DELETE SET NULL')
        conn.execute('UPDATE chauffeurs SET tracteur_attitre_id = tracteur_id')
    if 'remorque_attitree_id' not in colonnes:
        conn.execute('ALTER TABLE chauffeurs ADD COLUMN remorque_attitree_id INTEGER REFERENCES remorques(id) ON DELETE SET NULL')
        conn.execute('UPDATE chauffeurs SET remorque_attitree_id = remorque_id')
    if 'derniere_utilisation' not in colonnes:
        conn.execute('ALTER TABLE chauffeurs ADD COLUMN derniere_utilisation TEXT')
    conn.commit()


def seed_admin(identifiant=None, mot_de_passe=None):
    """Crée le tout premier compte modérateur si la base est vide.
    En production, définissez ADMIN_IDENTIFIANT et ADMIN_MOTDEPASSE en variables
    d'environnement plutôt que de garder les valeurs de démonstration par défaut."""
    identifiant = identifiant or os.environ.get('ADMIN_IDENTIFIANT', 'admin')
    mot_de_passe = mot_de_passe or os.environ.get('ADMIN_MOTDEPASSE', 'blondel2026')
    from werkzeug.security import generate_password_hash
    conn = get_connection()
    existe = conn.execute(
        "SELECT id FROM utilisateurs WHERE role = 'moderateur' LIMIT 1"
    ).fetchone()
    if not existe:
        conn.execute(
            "INSERT INTO utilisateurs (identifiant, mot_de_passe_hash, role) VALUES (?, ?, 'moderateur')",
            (identifiant, generate_password_hash(mot_de_passe))
        )
        conn.commit()
        print(f"Compte modérateur initial créé : {identifiant} / {mot_de_passe}")
    conn.close()
