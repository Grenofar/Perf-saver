#!/usr/bin/env bash
# Compile Perf Saver pour Windows depuis Linux (mingw-w64 + NSIS) et produit :
#   dist/PerfSaver-Setup-<version>.exe   et   dist/PerfSaver-portable-<version>.zip
set -euo pipefail
cd "$(dirname "$0")"
VERSION=$(grep -m1 '^version' src-tauri/Cargo.toml | cut -d'"' -f2)
python3 scripts/gen_legal.py
EXTRA=()
if ! rustup target list --installed 2>/dev/null | grep -q x86_64-pc-windows-gnu; then
  # Pas de bibliothèque standard Windows précompilée : on la compile depuis les sources.
  export RUSTC_BOOTSTRAP=1
  EXTRA=(-Zbuild-std=std,panic_abort)
fi
(cd src-tauri && cargo build --release "${EXTRA[@]}")
OUT=src-tauri/target/x86_64-pc-windows-gnu/release
rm -rf dist && mkdir -p dist
cp "$OUT/perfsaver.exe" dist/PerfSaver.exe
cp "$OUT/WebView2Loader.dll" dist/
(cd installer && makensis -V2 -DVERSION="$VERSION" -DSRC=../dist setup.nsi)
(cd dist && zip -q "PerfSaver-portable-$VERSION.zip" PerfSaver.exe WebView2Loader.dll)
(cd dist && sha256sum PerfSaver-Setup-"$VERSION".exe PerfSaver-portable-"$VERSION".zip > SHA256SUMS.txt)
ls -la dist

# Met à jour le site de téléchargement (site/) avec ce build
cp "dist/PerfSaver-Setup-$VERSION.exe" site/download/PerfSaver-Setup.exe
SHA=$(sha256sum "dist/PerfSaver-Setup-$VERSION.exe" | cut -d' ' -f1)
sed -i -E "s#(<span data-v>)[^<]*(</span>)#\1$VERSION\2#g; s#(<code data-sha>)[^<]*(</code>)#\1$SHA\2#" site/index.html
echo "Site mis à jour : version $VERSION, SHA-256 $SHA"

# Manifeste lu par l'application pour les mises à jour automatiques
cat > site/latest.json <<JSON
{
  "version": "$VERSION",
  "url": "/download/PerfSaver-Setup.exe",
  "sha256": "$SHA",
  "date": "$(date -u +%Y-%m-%d)",
  "notes": "Voir les nouveautés sur le site."
}
JSON
