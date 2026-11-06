#!/usr/bin/env python3
"""Génère installer/LICENCE.txt et site/conditions.html à partir de docs/CONDITIONS.md + LICENSE."""
import html, re, pathlib
root = pathlib.Path(__file__).resolve().parent.parent
md = (root / "docs/CONDITIONS.md").read_text(encoding="utf-8")
lic = (root / "LICENSE").read_text(encoding="utf-8")

# Texte brut pour la page de licence de l'installeur (CRLF + BOM pour NSIS)
t = re.sub(r"^#+ ", "", md, flags=re.M).replace("**", "").replace("*", "").replace("`", "")
(root / "installer/LICENCE.txt").write_text((t + "\n\n" + "-" * 40 + "\n\n" + lic).replace("\n", "\r\n"), encoding="utf-8-sig", newline="")

# Page HTML du site
page = (root / "site/conditions.html").read_text(encoding="utf-8")
body = []
for block in md.split("\n\n"):
    b = block.strip()
    if not b or b.startswith("# ") or b.startswith("*Version"):
        continue
    if b.startswith("## "):
        body.append(f"<h2>{html.escape(b[3:])}</h2>")
        continue
    x = html.escape(b)
    x = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", x)
    x = re.sub(r"`(.+?)`", r"<code>\1</code>", x).replace("(voir <code>LICENSE</code>)", "(texte complet ci-dessous)")
    body.append(f"<p>{x}</p>")
body.append("<h2>8. Utilisation du site</h2><p>Le site permet de découvrir et de télécharger le logiciel. Son contenu est fourni à titre informatif ; l'éditeur ne garantit pas son exactitude ni sa disponibilité permanente et décline toute responsabilité, dans les limites permises par la loi, quant à l'usage qui en est fait. Le fichier proposé au téléchargement est accompagné de son empreinte SHA-256, qui permet de vérifier qu'il n'a pas été modifié.</p>")
body.append(f'<h2>Licence MIT</h2><div class="box"><pre style="white-space:pre-wrap;margin:0;font-size:12.5px;color:var(--mute)">{html.escape(lic)}</pre></div>')
start = page.index('<p class="date">')
start = page.index("</p>", start) + 4
end = page.index("</main>")
(root / "site/conditions.html").write_text(page[:start] + "\n" + "\n".join(body) + "\n" + page[end:], encoding="utf-8")
print("Textes légaux régénérés")
