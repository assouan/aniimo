# Évaluation du loader IL2CPP

BepInEx `6.0.0-pre.2`, variante officielle `Unity.IL2CPP-win-x64`, est retenu comme candidat plutôt qu’un loader local réécrit. L’archive officielle inspectée fait 34 146 254 octets et porte le SHA-256 `616ec7eb06cf11b2a0000e8fcef04d1b12bb58e84a2e0bdac9523234fc193ceb`.

Elle embarque `BepInEx.Core` et `BepInEx.Unity.IL2CPP` version assembly `6.0.0.0`, `Il2CppInterop.Runtime` `1.4.6.0` et `Cpp2IL.Core` `2022.1.0.0`. Ce couple embarqué est conservé comme unité candidate ; le pipeline ne substitue pas silencieusement une version Il2CppInterop plus récente.

La documentation officielle BepInEx indique que le support Unity IL2CPP utilise les builds correspondants et que le premier lancement génère les fichiers d’interop. Aniimo présente des métadonnées classées `suspected_protection`; cette génération n’est donc pas réputée fonctionnelle par simple sélection du loader.

Statut : `selected_candidate`, `not_installed`, validation runtime `not_tested`. Aucune archive n’a été extraite dans l’installation du jeu, aucune DLL n’a été injectée et aucun processus Aniimo n’a été démarré.

Sources primaires :

- https://docs.bepinex.dev/master/articles/user_guide/installation/unity_il2cpp.html
- https://github.com/BepInEx/BepInEx/releases/tag/v6.0.0-pre.2
- https://github.com/BepInEx/Il2CppInterop
