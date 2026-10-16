# Migrations du registre

Les migrations SQLite seront ajoutées pendant M1 sous forme de fichiers ordonnés et immuables. Chaque migration doit être transactionnelle, activer les clés étrangères, disposer d'un test depuis la version précédente et produire une sauvegarde cohérente avant application sur un registre réel.

Ne pas modifier une migration déjà publiée. Ajouter une migration corrective.
