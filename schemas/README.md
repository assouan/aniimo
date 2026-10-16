# Schémas d'échange

Ce dossier recevra pendant M1 les JSON Schema versionnés de tous les artefacts canoniques : profil, snapshot, détection, plan, preuves, sorties d'étapes, symboles, changements et validations.

M-1 ne crée pas de schéma fictif avant l'existence des producteurs/consommateurs. Toute implémentation M1 devra :

- utiliser une URI/version de schéma stable ;
- rejeter les champs obligatoires absents et les versions inconnues ;
- conserver explicitement `null` pour une valeur inconnue ;
- tester les migrations et la compatibilité des lecteurs ;
- interdire les chemins absolus et les traversées de répertoire dans les artefacts publiés.
