import os
from functools import wraps
from flask import request, jsonify, g
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from database import get_connection

# En production, définissez la variable d'environnement SECRET_KEY avec une vraie valeur aléatoire
# (ex. générée avec `python3 -c "import secrets; print(secrets.token_hex(32))"`).
# Sans cette variable, une clé de secours est utilisée — à ne JAMAIS garder telle quelle en ligne.
SECRET_KEY = os.environ.get('SECRET_KEY', 'a-changer-en-production-avec-une-vraie-cle-secrete')
TOKEN_MAX_AGE = 60 * 60 * 24 * 60  # 60 jours — permet à l'app de "se souvenir" du chauffeur durablement

serializer = URLSafeTimedSerializer(SECRET_KEY)


def generer_token(utilisateur_id, role):
    return serializer.dumps({'utilisateur_id': utilisateur_id, 'role': role})


def verifier_token(token):
    try:
        return serializer.loads(token, max_age=TOKEN_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None


def authentification_requise(roles_autorises=None):
    """Décorateur : vérifie le jeton Bearer et charge l'utilisateur courant dans g.user"""
    def decorateur(fonction):
        @wraps(fonction)
        def enveloppe(*args, **kwargs):
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return jsonify({'erreur': 'Authentification requise'}), 401
            token = auth_header.removeprefix('Bearer ').strip()
            donnees = verifier_token(token)
            if not donnees:
                return jsonify({'erreur': 'Jeton invalide ou expiré'}), 401
            if roles_autorises and donnees['role'] not in roles_autorises:
                return jsonify({'erreur': 'Accès non autorisé pour ce rôle'}), 403
            g.user = donnees
            return fonction(*args, **kwargs)
        return enveloppe
    return decorateur
