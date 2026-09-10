-- ============================================================
-- Transports A.Blondel — Schéma de base de données
-- ============================================================

PRAGMA foreign_keys = ON;

-- --- Comptes utilisateurs (modérateurs et chauffeurs) ---
CREATE TABLE IF NOT EXISTS utilisateurs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifiant TEXT UNIQUE NOT NULL,
    mot_de_passe_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('moderateur', 'chauffeur')),
    actif INTEGER NOT NULL DEFAULT 1,
    cree_le TEXT NOT NULL DEFAULT (datetime('now'))
);

-- --- Chauffeurs (fiche complète, liée à un compte utilisateur) ---
CREATE TABLE IF NOT EXISTS chauffeurs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    utilisateur_id INTEGER REFERENCES utilisateurs(id) ON DELETE SET NULL,
    nom_complet TEXT NOT NULL,
    telephone TEXT,
    numero_permis TEXT,
    tracteur_id INTEGER REFERENCES tracteurs(id) ON DELETE SET NULL,
    remorque_id INTEGER REFERENCES remorques(id) ON DELETE SET NULL,
    cree_le TEXT NOT NULL DEFAULT (datetime('now'))
);

-- --- Tracteurs routiers ---
CREATE TABLE IF NOT EXISTS tracteurs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    immatriculation TEXT UNIQUE NOT NULL,
    modele TEXT,
    kilometrage INTEGER DEFAULT 0,
    date_controle_technique TEXT,
    date_rdv_controle_technique TEXT,
    date_assurance TEXT,
    date_extincteur TEXT,
    date_chronotachygraphe TEXT,
    date_tachylimiteur TEXT,
    cree_le TEXT NOT NULL DEFAULT (datetime('now'))
);

-- --- Remorques ---
CREATE TABLE IF NOT EXISTS remorques (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    immatriculation TEXT UNIQUE NOT NULL,
    type TEXT,
    tracteur_id INTEGER REFERENCES tracteurs(id) ON DELETE SET NULL,
    date_controle_technique TEXT,
    date_rdv_controle_technique TEXT,
    cree_le TEXT NOT NULL DEFAULT (datetime('now'))
);

-- --- Documents personnels des chauffeurs (dates d'échéance) ---
CREATE TABLE IF NOT EXISTS documents_chauffeurs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chauffeur_id INTEGER NOT NULL REFERENCES chauffeurs(id) ON DELETE CASCADE,
    carte_identite TEXT,
    permis TEXT,
    passeport TEXT,
    carte_conducteur TEXT,
    adr TEXT,
    chronotachygraphe TEXT,
    UNIQUE(chauffeur_id)
);

-- --- Missions ---
CREATE TABLE IF NOT EXISTS missions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chauffeur_id INTEGER NOT NULL REFERENCES chauffeurs(id) ON DELETE CASCADE,
    date_mission TEXT NOT NULL,
    heure_depart TEXT,
    client TEXT,
    adresse TEXT,
    chef_de_chantier TEXT,
    document_url TEXT,
    statut TEXT NOT NULL DEFAULT 'a_venir' CHECK(statut IN ('a_venir', 'en_cours', 'livree', 'incident')),
    acceptee INTEGER NOT NULL DEFAULT 0,
    acceptee_le TEXT,
    realisee INTEGER NOT NULL DEFAULT 0,
    realisee_le TEXT,
    nombre_tours INTEGER,
    remarque TEXT,
    cree_le TEXT NOT NULL DEFAULT (datetime('now'))
);

-- --- Déclarations de journée (prise/fin de service, kilométrage) ---
CREATE TABLE IF NOT EXISTS declarations_journee (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chauffeur_id INTEGER NOT NULL REFERENCES chauffeurs(id) ON DELETE CASCADE,
    date_jour TEXT NOT NULL,
    heure_prise_service TEXT,
    heure_fin_service TEXT,
    km_depart INTEGER,
    km_arrivee INTEGER,
    tracteur_id INTEGER REFERENCES tracteurs(id) ON DELETE SET NULL,
    UNIQUE(chauffeur_id, date_jour)
);

-- --- Indemnités (frais de route) déclarées par jour ---
CREATE TABLE IF NOT EXISTS indemnites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chauffeur_id INTEGER NOT NULL REFERENCES chauffeurs(id) ON DELETE CASCADE,
    date_jour TEXT NOT NULL,
    casse_croute INTEGER NOT NULL DEFAULT 0,
    repas_nuit INTEGER NOT NULL DEFAULT 0,
    repas INTEGER NOT NULL DEFAULT 0,
    petit_decouche INTEGER NOT NULL DEFAULT 0,
    grand_decouche INTEGER NOT NULL DEFAULT 0,
    commentaire TEXT,
    UNIQUE(chauffeur_id, date_jour)
);

-- --- Achats déclarés (pro ou perso) ---
CREATE TABLE IF NOT EXISTS achats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chauffeur_id INTEGER NOT NULL REFERENCES chauffeurs(id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK(type IN ('pro', 'perso')),
    date_achat TEXT NOT NULL,
    description TEXT,
    montant REAL NOT NULL,
    cree_le TEXT NOT NULL DEFAULT (datetime('now'))
);

-- --- Pleins de carburant ---
CREATE TABLE IF NOT EXISTS pleins_carburant (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tracteur_id INTEGER NOT NULL REFERENCES tracteurs(id) ON DELETE CASCADE,
    chauffeur_id INTEGER REFERENCES chauffeurs(id) ON DELETE SET NULL,
    type_carburant TEXT NOT NULL DEFAULT 'gazoil' CHECK(type_carburant IN ('gazoil', 'adblue')),
    date_plein TEXT NOT NULL,
    kilometrage INTEGER,
    litres REAL,
    prix_total REAL,
    cree_le TEXT NOT NULL DEFAULT (datetime('now'))
);

-- --- Facturation ---
CREATE TABLE IF NOT EXISTS facturation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id INTEGER REFERENCES missions(id) ON DELETE SET NULL,
    chauffeur_id INTEGER NOT NULL REFERENCES chauffeurs(id) ON DELETE CASCADE,
    date_mission TEXT NOT NULL,
    client TEXT NOT NULL,
    numero_facture TEXT,
    date_facturation TEXT,
    cree_le TEXT NOT NULL DEFAULT (datetime('now'))
);
