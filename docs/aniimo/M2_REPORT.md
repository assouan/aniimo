# Rapport M2 — analyse native approuvée

Date de validation : 2026-10-17

## Résultat

M2 est validé sur le snapshot immuable `snapshot-58a1510492a6987eb006e0ff901702f35bec414a416e184558ccdb1a4ca12adf`, build canonique `build-6153068c4ea08c06123406e0873b667f6db5b02bb3d17aa71833d565ec3838ec`.

L’analyse publiée porte la clé `m2-1da93dfb99e195f8f9a34fedd558dd8b3d6d868ea7f67c196d5167ab3de2e03e`. Elle contient uniquement les quatre modules natifs explicitement approuvés. Aucun corps de `GameAssembly.dll`, Unity, .NET/IL2CPP générique, xLua standard ou autre bibliothèque tierce n’a été exporté.

Le couple IL2CPP courant reste classé `suspected_protection`. Le magic est standard, mais le second mot vaut exactement la taille du fichier de métadonnées, la structure n’est pas conforme et l’échantillon de 1 MiB présente une entropie de `7,960927` bits/octet. Aucun catalogue managé, stub ou fallback approximatif n’a été publié. Cette limite n’empêche pas l’analyse complète des quatre modules approuvés indépendants.

## Couverture native réelle

| Module approuvé | Corps | `c_and_asm` | `asm_only` | `disassembly_failed` | `pending` |
|---|---:|---:|---:|---:|---:|
| `KernelDumpAnalyzer.exe` | 98 | 98 | 0 | 0 | 0 |
| `NEP2.dll` | 45 790 | 45 772 | 3 | 15 | 0 |
| `NEPCleaner.exe` | 666 | 666 | 0 | 0 | 0 |
| `NEPKernel.sys` | 6 785 | 6 758 | 0 | 27 | 0 |
| **Total** | **53 339** | **53 294** | **3** | **42** | **0** |

La réconciliation est exacte et les catégories sont exclusives. Les 3 corps `asm_only` possèdent leur ASM et leur diagnostic. Les 42 `disassembly_failed` sont conservés comme échecs explicites ; aucun fichier C vide ou tronqué n’est compté comme succès. La file difficile a tenté un corps NEP2 sans transformer son timeout et un corps NEPKernel avec succès. Aucun corps ne reste `pending`.

Le registre contient également :

- 910 614 références natives conservées comme références, dont les cibles hors plage SQLite restent dans leur preuve brute ;
- 45 672 régions non résolues ou non attribuées, séparées de la couverture des corps reconnus ;
- 53 339 identités persistantes de corps, observations, tentatives et liens de symboles natifs ;
- quatre analyses de module et quatre signatures BSim : `medium_64` pour les trois modules x86-64 et `medium_32` pour `NEPCleaner.exe`.

`discovery_complete` reste volontairement faux : l’absence de catalogue IL2CPP interdit de prétendre connaître toutes les méthodes attendues, et les plages/cibles non résolues sont rapportées séparément.

## Sorties

La vue utilisateur se trouve sous :

`output/builds/build-6153068c4ea08c06123406e0873b667f6db5b02bb3d17aa71833d565ec3838ec/m2-1da93dfb99e195f8f9a3/`

Elle contient 476 978 fichiers. Chaque corps possède un manifeste, un diagnostic, ses références, son prototype natif, l’état de sa signature managée et, selon son état, son ASM et son pseudocode C. Les vues `by-module` et `unnamed` lient directement ces éléments. Les noms C++ trop longs sont bornés à l’aide d’un suffixe SHA-256 stable ; le composant de chemin maximal mesuré fait 92 octets.

Les agrégats principaux sont `coverage.json`, `native_bodies.csv`, `native_locations.csv`, `native_prototypes.csv`, `symbol_body_links.csv`, `references.csv`, `metadata/adapter-result.json` et `native/bsim-index.json`. Le C est étiqueté comme pseudocode Ghidra, jamais comme source original ou code prouvé compilable.

Un bundle reproductible et récupérable est conservé sous `.aitools/bundles/aniimo-m2-1da93dfb99e195f8.tar.gz` :

- taille : 129 835 076 octets ;
- SHA-256 : `2b138c092a83f87b3b5aa290dee802905e08724df20c7f80fac12d9a59093159` ;
- contenu non compressé : environ 2,5 Gio.

## Incrémentalité et publication

Le run de publication `run-m2-real-i` a repris les quatre intermédiaires Ghidra/BSim validés, sans relancer Java : 53 339 corps publiés en `721 528,169 ms`, dont `672 041,544 ms` pour les 476 978 fichiers utilisateurs. Le run final `run-m2-real-k` a terminé en `2 079,976 ms` : les quatre modules et la publication sont `cache_hit`, la clé d’analyse est identique et les digests/mtimes des sentinelles n’ont pas changé.

Les sentinelles avant/après cache valent :

- `analysis-manifest.json` : SHA-256 `c9de3f60ba9529c532a319af8363ef6220be1b90fc102b7641e6865e486a957e`, mtime brut `1792196449` ;
- `coverage.json` : SHA-256 `ad3c64bb3b01052f2727892faf18192f31d37ab04064d4f47ab0314215175a31`, même mtime brut.

La publication écrit directement dans un staging invisible, effectue une barrière groupée puis renomme le dossier. Les manifests de corps sont hashés dans le manifeste d’analyse sans être inutilement dupliqués dans le CAS ; ASM, C, bundles de module et signatures BSim restent adressés par contenu.

## Outils et image

- Ghidra / BSim : `12.1.4 PUBLIC` ;
- Microsoft OpenJDK : `25.0.4+7-LTS` ;
- image analyseur finale : `sha256:a9a985611751f76b1af44319011adc022c152db01501191542af6c02878bd5af` ;
- SBOM SPDX : `.aitools/sbom/analyzer-m2.spdx.json`, SHA-256 `b1e1458c18e8e6f5ae5b49f1ce42e506dad9834b6ca9405a8c02f08988ec0dda` ;
- script d’audit : `tools/audit_m2.py`.

L’analyse réelle a utilisé un rootfs read-only, UID/GID 1000, réseau `none`, `/inputs` read-only et aucun montage du jeu ou de Steam. L’installation live n’a pas été modifiée et aucun code extrait n’a été exécuté.

## Validations exécutées

| Contrôle | Résultat |
|---|---|
| `python -m ruff check modkit tests tools/audit_m2.py` | aucun diagnostic |
| `python -m unittest discover -s tests -v` | 33 tests réussis en 2,961 s |
| `tools/audit_m2.py` sur le volume puis sur l’export NTFS | deux audits identiques ; intégrité SQLite et clés étrangères OK |
| Réconciliation couverture/registre/fichiers | 53 339 = 53 294 + 3 + 42 + 0 |
| Audit de périmètre | exactement quatre modules approuvés |
| Audit de chemins hôte | zéro occurrence du chemin racine hôte dans l’analyse publiée |
| Test archive TAR.GZ | archive lisible puis export intégral réaudité |
| Second run réel | quatre modules et publication en cache, aucune réécriture |

## Incidents corrigés et limite opérationnelle

Les runs intermédiaires ont révélé puis couvert par test : une cible RVA non représentable dans un entier SQLite signé, des recherches SQL sans index composite, une réingestion inutile sur cache complet, des `fsync` par fichier et des noms C++ dépassant 255 octets. Les rapports d’échec disponibles restent sous `output/reports/`.

Un appel de diagnostic `docker top` de Docker Desktop a laissé un ancien conteneur en sommeil noyau non interruptible sur le volume `aniimo-state`. Pour ne pas redémarrer Docker et perturber des services hors périmètre, le registre validé M2 est conservé dans `aniimo-state-m2b`; l’ancien registre est resté intact. Les jalons statiques suivants utilisent ce volume validé jusqu’à un futur redémarrage contrôlé de Docker.

## Suite

M3 peut maintenant comparer des builds, produire des candidats explicables, invalider signatures/layouts/références et régénérer uniquement la documentation dépendante. Aucun score BSim ne sera promu automatiquement en identité ou en hook.
