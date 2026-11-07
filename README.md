<p align="center">
  <img src="src-tauri/icons/icon.png" width="96" alt="Perf Saver">
</p>

<h1 align="center">Perf Saver</h1>

<p align="center">
  Optimiseur Windows léger pour le jeu — un clic pour libérer ton PC pendant que tu joues.<br>
  <b>Rust + Tauri 2</b> · ~3 Mo · aucune donnée envoyée · tout est réversible
</p>

---

## Fonctionnalités

| | |
|---|---|
| **Mode jeu** | Ferme les applis choisies, met en pause les services superflus (SysMain, indexation, télémétrie, Windows Update…), passe l'alimentation en hautes performances, met le jeu en priorité haute et l'arrière-plan en priorité basse, libère la RAM. Tout est restauré à la désactivation. |
| **Ce qui ralentit** | Liste des programmes gourmands, des applications lancées au démarrage et des services non essentiels, avec une action pour chacun. |
| **Processus** | Vue regroupée par programme, triable par CPU / mémoire, avec une catégorie (Jeu, Inutile, Matériel/RGB, Application, Launcher, Windows). |
| **Démarrage** | Active / désactive les programmes lancés avec Windows (même mécanisme que le Gestionnaire des tâches). |
| **Services** | Services Windows non essentiels et services installés par des logiciels. |
| **Sécurité** | Détecte les faux processus système (ex. `svchost.exe` hors de `System32`), les noms imités et les programmes lancés depuis un dossier temporaire. |
| **Zone de notification** | L'icône près de l'horloge permet d'activer le mode jeu ou de libérer la RAM sans ouvrir la fenêtre. Fermer la fenêtre réduit l'application à cet endroit. |
| **Mises à jour automatiques** | Détecte une nouvelle version, télécharge l'installeur, vérifie son SHA-256, l'installe en silencieux et relance l'app — en un clic. |
| **Démarrage avec Windows** | Proposé une seule fois au premier lancement, modifiable dans Paramètres. |

### Garde-fous
- Les processus essentiels de Windows et les anti-triches (Vanguard, BattlEye, EasyAntiCheat, FACEIT) ne peuvent pas être fermés.
- Aucun service n'est désactivé de façon permanente : ils sont seulement arrêtés, puis relancés.
- Rien n'est désinstallé, aucun fichier système n'est modifié.

## Installation

Site officiel : **https://perf-saver.vercel.app**

Ou télécharge la dernière version dans **[Releases](../../releases/latest)** :

- `PerfSaver-Setup-x.y.z.exe` — installeur (raccourcis Bureau et menu Démarrer, désinstallation propre)
- `PerfSaver-portable-x.y.z.zip` — version sans installation

L'application demande les droits administrateur, nécessaires pour gérer les services et les priorités. Le logiciel n'étant pas signé numériquement, Windows SmartScreen peut afficher un avertissement : *Informations complémentaires* → *Exécuter quand même*.

**Configuration requise :** Windows 10 / 11 64 bits avec le runtime Microsoft Edge WebView2 (installé d'office sur Windows 11).

## Confidentialité

Perf Saver fonctionne **en local** : aucune télémétrie, aucun compte. Sa seule connexion est la vérification des mises à jour (lecture de `latest.json` sur le site, désactivable dans Paramètres). Les réglages sont stockés dans `%LOCALAPPDATA%\PerfSaver` (supprimable à tout moment).

## Compiler

### Sous Windows
```powershell
# Prérequis : Rust (rustup.rs) + Visual Studio Build Tools (C++)
cargo install tauri-cli --version "^2"
cd src-tauri
# retirer la cible gnu de src-tauri/.cargo/config.toml pour utiliser MSVC
cargo tauri build --no-bundle
```

### Sous Linux (compilation croisée, utilisée par la CI)
```bash
sudo apt install mingw-w64 nsis zip
rustup target add x86_64-pc-windows-gnu
./build.sh          # → dist/PerfSaver-Setup-x.y.z.exe
```

Publier une version : change `version` dans `src-tauri/Cargo.toml` et pousse sur `main` — le workflow GitHub Actions compile et crée la release `vX.Y.Z` automatiquement.

## Structure

```
ui/                  interface (HTML/CSS/JS, sans framework)
src-tauri/src/       backend Rust (processus, services, démarrage, mode jeu, zone de notification)
src-tauri/src/lists.rs   listes de classification des programmes et services
installer/           script NSIS de l'installeur
site/                site de téléchargement (déployé sur Vercel)
docs/                conditions d'utilisation, notes de version
```

## Avertissement

Logiciel fourni **« en l'état », sans aucune garantie**. L'utilisateur est seul responsable des actions qu'il déclenche (fermeture de programmes, arrêt de services, etc.). Dans toute la mesure permise par la loi, l'auteur décline toute responsabilité pour tout dommage lié à son utilisation. Voir [docs/CONDITIONS.md](docs/CONDITIONS.md).

Perf Saver n'est affilié ni à Microsoft ni aux éditeurs des logiciels cités ; les marques appartiennent à leurs propriétaires respectifs.

## Licence

[MIT](LICENSE) © 2026 Grenofar
