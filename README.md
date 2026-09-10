# Transports A.Blondel — API backend

Ceci est le **vrai backend** de l'application, qui remplace les données factices des maquettes HTML par une vraie base de données persistante (SQLite) et une vraie API (Flask), avec authentification par mot de passe haché et jetons de session.

Ce backend a été **écrit et testé dans l'environnement de développement** (création de comptes, chauffeurs, tracteurs, missions, acceptation, validation, facturation automatique — tout fonctionne de bout en bout).

## Ce qui est déjà fonctionnel (écrit ET testé de bout en bout)

- **Authentification** : comptes modérateur et chauffeur, mots de passe hachés (jamais stockés en clair), jetons de session signés (12h de validité)
- **Chauffeurs** : création (avec création automatique du compte mobile associé), liste, suppression, affectation d'un véhicule
- **Tracteurs routiers** : création, liste, suppression
- **Remorques** : création, liste, suppression
- **Missions** : création par le modérateur, acceptation par le chauffeur, validation de fin de mission (nombre de tours, remarque)
- **Facturation** : ligne créée **automatiquement** à la validation d'une mission ; saisie du numéro de facture et de la date de facturation
- **Déclarations de journée** : kilométrage départ/arrivée, avec **reprise automatique du km départ du lendemain** si le même tracteur est utilisé (testé et vérifié)
- **Indemnités** : déclaration par le chauffeur (casse-croûte, repas, découchés...), calcul automatique du total selon le vrai barème, consultation filtrée par mois côté modérateur
- **Achats** (pro / perso) : déclaration par le chauffeur, consultation filtrée par type et par mois
- **Pleins de carburant** : enregistrement, et **agrégation TICPE** (litrage total par tracteur et par mois/année)
- **Documents** : dates d'échéance des chauffeurs (carte d'identité, permis, ADR...) et des tracteurs (assurance, contrôle technique, extincteur...)
- **Historique** : vue combinée missions + frais, triée par date

## Ce qu'il reste à construire (sur le même modèle)

- Remorques : dates d'échéance (même principe que les tracteurs)
- Endpoints de mise à jour/suppression fine (ex. modifier une déclaration déjà envoyée)
- Endpoint dédié à la synthèse consommation (moyenne L/100km par véhicule et par chauffeur — actuellement calculable côté frontend à partir de `/api/pleins`)

Tout ce qui suit reste à écrire, mais sur exactement le même principe que les routes existantes dans `app.py` — chaque nouvelle table du schéma appelle le même schéma : route GET (liste, avec filtre par rôle), route POST (création), et éventuellement PATCH/PUT (mise à jour).

## Référence des endpoints disponibles

| Méthode | Route | Qui | Description |
|---|---|---|---|
| POST | `/api/auth/login` | Tous | Connexion |
| GET | `/api/chauffeurs` | Tous | Liste des chauffeurs |
| POST | `/api/chauffeurs` | Modérateur | Créer un chauffeur (+ compte mobile) |
| DELETE | `/api/chauffeurs/<id>` | Modérateur | Supprimer un chauffeur |
| PATCH | `/api/chauffeurs/<id>/vehicule` | Tous | Affecter tracteur/remorque |
| GET/POST | `/api/tracteurs` | Tous / Modérateur | Liste / création |
| DELETE | `/api/tracteurs/<id>` | Modérateur | Suppression |
| GET/POST | `/api/remorques` | Tous / Modérateur | Liste / création |
| DELETE | `/api/remorques/<id>` | Modérateur | Suppression |
| GET/POST | `/api/missions` | Tous / Modérateur | Liste (filtrée par rôle) / création |
| PATCH | `/api/missions/<id>/accepter` | Chauffeur | Accepter sa mission |
| PATCH | `/api/missions/<id>/valider` | Chauffeur/Modérateur | Valider (crée la facturation) |
| GET | `/api/facturation` | Modérateur | Liste des lignes à facturer |
| PATCH | `/api/facturation/<id>` | Modérateur | Saisir n° facture + date |
| GET | `/api/declarations/aujourdhui` | Chauffeur | Déclaration du jour + km suggéré |
| POST | `/api/declarations/km-depart` | Chauffeur | Déclarer le km départ |
| POST | `/api/declarations/km-arrivee` | Chauffeur | Déclarer le km arrivée |
| GET/POST | `/api/indemnites` | Tous / Chauffeur | Liste (avec total calculé) / déclaration |
| GET/POST | `/api/achats` | Tous / Chauffeur | Liste (filtrable) / déclaration |
| GET/POST | `/api/pleins` | Tous | Liste (filtrable) / enregistrement |
| GET | `/api/pleins/ticpe` | Modérateur | Litrage par tracteur et par mois |
| PUT/GET | `/api/documents/chauffeurs[/<id>]` | Modérateur | Dates d'échéance chauffeur |
| PUT | `/api/documents/tracteurs/<id>` | Modérateur | Dates d'échéance véhicule |
| GET | `/api/historique` | Modérateur | Vue combinée missions + frais |

## Installation et lancement en local

```bash
cd backend
python3 -m venv venv
source venv/bin/activate          # Windows : venv\Scripts\activate
pip install -r requirements.txt
python3 app.py
```

Le serveur démarre sur `http://127.0.0.1:5050` (ou sur le port de la variable `PORT` si définie). Au premier lancement, un compte modérateur est créé automatiquement :

- **Identifiant** : `admin` (personnalisable via la variable d'environnement `ADMIN_IDENTIFIANT`)
- **Mot de passe** : `blondel2026` (personnalisable via `ADMIN_MOTDEPASSE`)

Exemple avec des identifiants personnalisés :
```bash
ADMIN_IDENTIFIANT=blondel ADMIN_MOTDEPASSE=un-vrai-mot-de-passe python3 app.py
```

## Tester l'API

```bash
# Se connecter
curl -X POST http://127.0.0.1:5050/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifiant":"admin","mot_de_passe":"blondel2026"}'

# Utiliser le jeton reçu pour créer un chauffeur
curl -X POST http://127.0.0.1:5050/api/chauffeurs \
  -H "Authorization: Bearer VOTRE_JETON" \
  -H "Content-Type: application/json" \
  -d '{"nom_complet":"Nathan Lebreau","identifiant":"n.lebreau","mot_de_passe":"nathan2026"}'
```

## Relier les fichiers HTML existants à cette API

Les trois maquettes (`transport-dashboard.html`, `app-mobile-chauffeur.html`, `app-mobile-moderateur.html`) manipulent aujourd'hui des données en mémoire (tableaux JavaScript). Pour les connecter à cette vraie API, il faut remplacer ces manipulations locales par de vrais appels réseau, par exemple :

```javascript
const API_URL = 'http://127.0.0.1:5050/api'; // à remplacer par l'URL réelle une fois déployée
let token = localStorage.getItem('token'); // ou en mémoire, selon vos choix de sécurité

async function chargerChauffeurs() {
  const reponse = await fetch(`${API_URL}/chauffeurs`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const chauffeurs = await reponse.json();
  // ... construire le tableau HTML à partir de "chauffeurs" au lieu des données locales
}
```

C'est un travail de réécriture méthodique, section par section, qui peut se faire progressivement (une section à la fois, en gardant les autres sur données locales en attendant).

## Déployer réellement sur internet (pour que vos chauffeurs y accèdent)

Le backend est maintenant **prêt pour la production** : port configurable via la variable `PORT`, clé secrète et mot de passe admin configurables par variables d'environnement, `gunicorn` (serveur de production) inclus dans les dépendances, et un `Procfile` que la plupart des hébergeurs reconnaissent automatiquement.

### Étapes concrètes avec Render (recommandé pour démarrer, gratuit)

1. **Mettez ce dossier `backend/` dans un dépôt Git** (GitHub, GitLab...) — c'est la méthode que Render utilise pour déployer.
2. Sur [render.com](https://render.com), créez un compte, puis **« New + » → « Web Service »**, et connectez votre dépôt.
3. Render détecte le `Procfile` automatiquement. Renseignez :
   - **Build Command** : `pip install -r requirements.txt`
   - **Start Command** : (laissé vide, le `Procfile` s'en charge — ou `gunicorn app:app` si demandé)
4. Dans l'onglet **Environment**, ajoutez ces variables :
   - `SECRET_KEY` → générez-en une vraie avec `python3 -c "import secrets; print(secrets.token_hex(32))"`
   - `ADMIN_IDENTIFIANT` → votre identifiant modérateur définitif
   - `ADMIN_MOTDEPASSE` → un vrai mot de passe (à changer ensuite depuis l'app)
5. **Déployez.** Render vous donne une URL du type `https://transports-blondel-api.onrender.com`.
6. Dans les 3 fichiers HTML, remplacez `const API_URL = 'http://127.0.0.1:5050/api';` par `const API_URL = 'https://votre-url.onrender.com/api';`.

### Point d'attention important : la base de données SQLite

Sur les hébergeurs comme Render, le disque est **effacé à chaque redéploiement** par défaut (offre gratuite) — vos données disparaîtraient. Deux solutions :

- **Simple** : ajoutez un **disque persistant** sur Render (payant, quelques dollars/mois), monté sur le dossier du backend.
- **Plus robuste, recommandé si le projet grandit** : migrer vers **PostgreSQL**. Render propose une base PostgreSQL gratuite pour démarrer ; l'adaptation du code (`database.py`) demande de remplacer `sqlite3` par `psycopg2` ou d'utiliser un ORM comme SQLAlchemy — un chantier à part, mais qui suit exactement la même logique que ce qui existe déjà.

### Autres hébergeurs possibles

| Service | Gratuit pour démarrer | Notes |
|---|---|---|
| **Railway** | Crédit gratuit limité | Interface très agréable, PostgreSQL intégré facilement |
| **Fly.io** | Oui (petite conso) | Un peu plus technique, disques persistants inclus |
| **PythonAnywhere** | Oui | Simple pour Flask spécifiquement, mais moins adapté à SQLite en écriture fréquente |
| **Supabase** | Oui | Base PostgreSQL + authentification tout-en-un ; demande de réécrire la couche base de données |

## Sécurité — à vérifier avant toute mise en production réelle

- [x] `SECRET_KEY` configurable par variable d'environnement (fait)
- [x] Mot de passe admin configurable par variable d'environnement (fait)
- [x] Port configurable pour s'adapter à l'hébergeur (fait)
- [ ] Définir une vraie `SECRET_KEY` aléatoire sur l'hébergeur (ne jamais garder la valeur par défaut)
- [ ] Changer le mot de passe admin par défaut dès le premier déploiement
- [ ] Ajouter une limite de tentatives de connexion (anti-bruteforce)
- [ ] Restreindre `Access-Control-Allow-Origin` (actuellement `*`) aux domaines réels de vos applications une fois qu'elles ont une URL fixe
- [ ] Passer sur une vraie base de données persistante (disque payant ou PostgreSQL)

