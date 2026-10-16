# ADR 0002 — Compatibilité limitée aux dépendances d'une capacité

- Statut : accepted
- Date : 2026-10-16

## Contexte

Aniimo peut modifier ses archives Lua ou des assets sans changer `GameAssembly.dll`. Inversement, une modification de layout peut casser un hook dont le corps natif semble identique. Un booléen attaché au build entier est trop large et trop imprécis.

## Décision

Chaque capacité publique déclare ses symboles, corps, layouts, champs, données, bindings, composants, résolveurs, ABI et tests requis. Leur représentation canonique forme `capability_basis_id`.

Une validation porte sur cette base exacte et un environnement runtime. Son transfert vers un nouveau `build_id` exige une règle explicite prouvant que chaque dépendance est inchangée. Toute dépendance inconnue désactive la capacité affectée.

## Conséquences

- Un changement sans relation ne provoque pas un faux test de la capacité.
- Un build nouveau peut réutiliser une validation seulement avec des preuves exactes.
- Les manifests de plugins peuvent demander des capacités/version de contrat plutôt que des offsets.
