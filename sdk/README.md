# GameModAPI 1.1.0

L’API publique expose deux capacités en lecture seule et sans hook natif : `ILuaModuleCatalog` et `IBuildIdentity`. Un mod peut vérifier la présence et l’identité de contenu d’un module Lua, puis lire l’identité exacte du build/snapshot déclaré par l’adaptateur, sans connaître les archives, offsets ou objets internes du jeu.

`GameModAPI.Contracts.dll` cible `netstandard2.1`. L’ajout de `IBuildIdentity` est binaire-additif : l’assembly conserve la version `1.0.0.0`. Le test M6 charge réellement le mod `1.0.0` déjà compilé lors de M5, sans le recompiler, contre le runtime et l’adaptateur `1.1.0`. L’adaptateur charge uniquement les manifests de builds emballés avec le SDK et échoue fermé sur un build inconnu ou ambigu.

Les capacités restent `RequiresValidation` dans le processus Aniimo : les tests hors jeu valident le contrat, les hashes internes du package, le parsing des manifests et le même ancien binaire de mod sur deux builds, mais aucun loader n’a été installé et aucun test in-game n’a été exécuté. Le package indique donc `runtime_validation_status=not_tested` et l’autorisation externe reste `not_requested`.

Le package ne contient aucun binaire, script, archive, pseudocode ou donnée personnelle provenant du jeu. `modkit sdk-verify` vérifie son SHA-256 externe, son allowlist, ses limites de taille, ses chemins, ses timestamps déterministes et le hash de chaque entrée. La release locale reste explicitement `unsigned`; ce statut n’est pas confondu avec une autorisation de distribution.
