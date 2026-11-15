"""Restaure une sauvegarde dans la base en service.

Utilisation (dans le « Shell » du service backend sur Render, dossier du code) :
    python3 restaurer_sauvegarde.py                      -> liste les sauvegardes disponibles
    python3 restaurer_sauvegarde.py NOM_DU_FICHIER.db    -> restaure ce fichier

Avant de restaurer, une copie de sécurité de la base actuelle est faite (type « manuelle »), pour pouvoir revenir en arrière.
"""
import sqlite3
import sys

from database import DB_PATH
import sauvegardes


def main():
    if len(sys.argv) < 2:
        liste = sauvegardes.lister()
        if not liste:
            print('Aucune sauvegarde trouvée dans', sauvegardes.DOSSIER)
        for s in liste:
            print(f"{s['nom']}   ({s['type']}, {s['taille'] // 1024} Ko)")
        return
    chemin = sauvegardes.chemin_sauvegarde(sys.argv[1])
    if not chemin:
        print('Sauvegarde introuvable ou nom invalide. Lancez la commande sans argument pour voir la liste.')
        sys.exit(1)
    controle = sqlite3.connect(chemin)
    if controle.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
        print("Cette sauvegarde est abîmée : restauration annulée.")
        sys.exit(1)
    controle.close()
    copie = sauvegardes.creer_sauvegarde('manuelle')
    print('Copie de sécurité de la base actuelle :', copie)
    source = sqlite3.connect(chemin)
    cible = sqlite3.connect(DB_PATH)
    source.backup(cible)
    cible.close()
    source.close()
    print('Restauration terminée depuis', sys.argv[1])


if __name__ == '__main__':
    main()
