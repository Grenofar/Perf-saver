# CLAUDE.md — Perf Saver

Optimiseur Windows pour le jeu. Rust + Tauri 2, interface `ui/index.html` sans framework, site statique `site/` sur Vercel. Tout le texte visible (app, site, commits) est en **français**.

Une documentation interne détaillée peut exister en local dans `README-INTERNE.md` : **ne jamais l'ajouter au dépôt** (exclu via `.git/info/exclude`).

## Commandes
- Compiler + installeur + mise à jour du site : `./build.sh` (Linux, mingw-w64 + NSIS ; cible `x86_64-pc-windows-gnu`).
- Vérifier le JS de l'interface : extraire le `<script>` de `ui/index.html` et lancer `node --check`.
- Les captures du site (`site/img/*.webp`) se font en ouvrant `ui/index.html` avec un faux `window.__TAURI__`.

## Publier une version
1. Incrémenter la version dans `src-tauri/Cargo.toml` **et** `src-tauri/tauri.conf.json`.
2. `./build.sh` (met à jour `site/download/`, `site/latest.json`, version et SHA-256 dans `site/index.html`).
3. Commit + push sur `main` → Vercel redéploie le site (les apps installées voient la MAJ), GitHub Actions crée la release `vX.Y.Z`.
- Les tags git sont bloqués depuis l'environnement Claude : ne pas en créer.

## Règles impératives
- **Auteur des commits** : `Grenofar <225425113+Grenofar@users.noreply.github.com>`. Sinon Vercel (Hobby + dépôt privé) bloque le déploiement.
- **Sécurité des fermetures** : ne jamais fermer `SYSTEM` ni `KEEP` (`src-tauri/src/lists.rs`) ; un programme « autre » n'est proposé que s'il a une fenêtre visible ; toujours passer par la fenêtre de confirmation de l'UI (`confirmKill`) avant de fermer des applis.
- **Réversibilité** : les services sont arrêtés puis relancés, jamais désactivés ; rien n'est désinstallé ni supprimé.
- **Manifeste** : `src-tauri/app.manifest` reste en `asInvoker` (l'élévation se fait une seule fois dans `main()`).
- **Commandes Tauri** qui prennent le verrou `sys` : toujours `async` (sinon l'interface se fige).
- **`UPDATE_URL`** (`https://perf-saver.vercel.app/latest.json`) : ne pas changer, les versions installées en dépendent.
- **Légal** : source unique `docs/CONDITIONS.md` (régénérée par `scripts/gen_legal.py`). Si les conditions changent, mettre à jour aussi `#termsText` dans `ui/index.html` et incrémenter `TERMS_VERSION` dans `main.rs`. Toute nouvelle collecte de données ou connexion réseau doit d'abord être ajoutée à `site/confidentialite.html`.
- Fichiers générés, ne pas éditer à la main : `installer/LICENCE.txt`, `site/latest.json`, `site/download/PerfSaver-Setup.exe`.

## Design
Style Windows 11 sobre : gris neutres, un seul accent bleu discret (`--acc`), boutons principaux clairs, vert/rouge uniquement pour les états. Pas de néon, dégradés, halos, texte en dégradé ni grilles d'icônes colorées. Site en thème sombre neutre, sans ressource externe.

## Où ajouter quoi
- Jeu non reconnu → `GAMES` ou `GAME_DIRS` dans `lists.rs` (+ nom lisible dans `pretty_game()`).
- Appli à ne jamais fermer → `KEEP`.
- Appli inutile en jeu → `BLOAT` ; logiciel RGB/périphérique → `HARDWARE` ; service non essentiel → `SERVICES`.
