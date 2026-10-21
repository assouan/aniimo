# Schémas JSON

M1 publie les contrats versionnés suivants :

- `capture-manifest-v2.schema.json` pour les snapshots immuables et leur CAS d’entrée ;
- `handoff-v1.schema.json` pour la remise atomique du snapshot exact ;
- `analysis-plan-v1.schema.json` pour les décisions de périmètre et étapes planifiées ;
- `run-report-v1.schema.json` pour les rapports hiérarchiques et leurs métriques.

M2 ajoute `native-body-v1`, `native-coverage-v1` et `il2cpp-adapter-result-v1` pour verrouiller les états exclusifs par corps, la réconciliation de couverture et les catégories d’échec IL2CPP sans faux catalogue.

M3 ajoute `build-comparison-v1` pour les deux builds exacts, les comptes d’appariement et d’invalidation, l’algorithme d’empreinte strict et les limites qui interdisent de transformer une similarité statique en certification runtime.

M4 ajoute `lua-analysis-v1` pour le bilan statique et `lua-runtime-observation-v1` pour l’import strict d’une observation bornée issue d’un processus autorisé. Le second contrat impose une provenance build/snapshot/VM/scénario et interdit qu’une sonde se présente comme exhaustive.

M5 ajoute `sdk-capability-manifest-v1`, `sdk-test-report-v1` et `sdk-release-evidence-v1` pour relier contrat public, base exacte de capacité, même binaire de mod testé hors jeu sur deux builds, statut runtime et autorisation externe.

M6 ajoute les versions v2 de ces trois contrats, `sdk-package-manifest-v2` et `watch-state-v1` pour l’identité de build additive, le test d’un ancien mod non recompilé, les hashes internes de distribution et l’état opérationnel du watcher local.

La CLI valide en code les invariants de sécurité critiques avant publication ou consommation : identifiants et digests, sélection exacte, présence et taille des objets, confinement des chemins et champs obligatoires de remise. Les fichiers JSON Schema servent au contrôle indépendant et aux futurs consommateurs.
