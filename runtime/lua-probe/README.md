# Sonde d'observation Lua

Cette sonde est un composant runtime séparé de l'analyse statique. Elle n'a pas été exécutée par le pipeline M4 et son état initial est `not_tested`.

`probe.lua` retourne une bibliothèque sans effet au chargement. Un adaptateur explicitement autorisé doit appeler `capture(config)` sur le thread et dans l'état Lua corrects, puis sérialiser la table retournée vers le schéma `schemas/lua-runtime-observation-v1.schema.json`. L'adaptateur doit fournir les `snapshot_id`, `build_id`, `module_sha256`, bridge, identité de VM et scénario exacts.

Le parcours emploie uniquement `next`, `rawget` et `type` sur des tables déjà accessibles. Il est borné par profondeur, nombre d'entrées par table et nombre total d'observations. Il n'appelle aucune fonction ou getter découvert, ne charge aucun module, n'accède pas aux métatables et ne convertit pas les userdata. Les clés non textuelles sont comptées mais pas converties. Une absence dans un scénario ne constitue jamais une preuve de suppression.

Les observations ne peuvent être importées qu'avec `modkit lua-import` et seulement si leur build et leur snapshot correspondent à une capture déjà enregistrée. Une valeur de type fonction conserve la signature prudente `fun(...): any` : les types métier ne sont jamais déduits de `debug.getinfo`.

Cette livraison n'installe aucun loader, n'injecte aucun module, ne modifie pas le dossier Steam et ne démarre pas le jeu. Son exécution exige un jalon runtime distinct dans un environnement de jeu ou serveur autorisé.
