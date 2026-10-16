# ADR 0004 — Validation technique et autorisation externe séparées

- Statut : accepted
- Date : 2026-10-16

## Contexte

Le mod pourra être soumis au support pour autorisation auprès de l'environnement protégé par NEP. Cette procédure administrative intervient après la production d'un prototype testable et peut viser une version ou un artefact précis.

## Décision

Le développement, l'analyse statique et les tests dans un processus autorisé peuvent progresser sans autorisation de distribution. Le registre conserve toutefois deux états indépendants : validation technique des capacités et autorisation externe du package.

Une autorisation référence le SHA-256 exact du package, sa version, l'identité de signature déclarée, les builds visés, son statut et une preuve privée. Une nouvelle compilation reçoit un nouveau hash et doit être comparée au périmètre de l'autorisation ; le pipeline ne suppose pas sa validité.

Cette décision ne limite pas le périmètre de reverse engineering statique autorisé. Les changements runtime sont spécifiés et validés dans leur propre jalon.

## Conséquences

- Un prototype peut être construit avant la demande administrative.
- La publication peut exiger simultanément validation technique et autorisation externe.
- Les documents publics ne contiennent pas les échanges privés ou identifiants sensibles du support.
