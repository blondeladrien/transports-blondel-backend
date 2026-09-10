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
    """Crée les tables si elles n'existent pas encore."""
    conn = get_connection()
    with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()


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
