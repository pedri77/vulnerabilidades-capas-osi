"""Generate docs/index.html (self-contained static page for GitHub Pages) and docs/capas.md from data/.

Usage: python tools/generar.py
Stdlib + PyYAML. Every value from the data is HTML-escaped.
"""
from __future__ import annotations

import html
import sys
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "tools"))
from validar import validar_repo  # noqa: E402

ENLACES_HERMANOS = [
    ("Modelo OSI interactivo", "https://pedri77.github.io/modelo_OSI/"),
    ("Protección por capas OSI", "https://pedri77.github.io/Basicos_Proteccion_Capas_OSI/"),
    ("Security Manager Control (vertical VRT-OSI)", "https://github.com/pedri77/security-manager-control"),
]
NOMBRES_CONSULTA = {"nvd": "NVD", "euvd": "EUVD", "cisa_kev": "CISA KEV", "cvedetails": "CVE Details"}

e = html.escape


def cargar():
    d = RAIZ / "data"
    cat = yaml.safe_load((d / "capas.yaml").read_text(encoding="utf-8"))
    fue = yaml.safe_load((d / "fuentes.yaml").read_text(encoding="utf-8"))
    ver = yaml.safe_load((d / "verificacion_ids.yaml").read_text(encoding="utf-8"))
    smc = yaml.safe_load((d / "smc_protocolos.yaml").read_text(encoding="utf-8"))
    return cat, fue, ver, {p["id"]: p for p in smc["protocolos"]}


def nombre_corto(titulo: str, ident: str) -> str:
    """'CWE - CWE-79: Improper ... (5.0)' -> 'Improper ...'; 'Network Sniffing, Technique T1040 - ...' -> 'Network Sniffing'."""
    t = titulo
    if t.startswith("CWE - "):
        t = t.split(": ", 1)[-1].rsplit(" (", 1)[0]
    else:
        t = t.split(f", Technique {ident}")[0].split(f", Sub-technique {ident}")[0]
    return t.strip()


def a(url: str, texto: str) -> str:
    return f'<a href="{e(url)}" rel="noopener">{e(texto)}</a>'


def etiqueta_capa(capa: dict) -> str:
    return "Transversal" if capa["numero"] is None else f"Capa {capa['numero']} · {capa['nombre']}"


def html_pagina(cat, fue, ver, smc) -> str:
    cwe = {r["id"]: r for r in ver["cwe"]}
    att = {r["id"]: r for r in ver["attack"]}
    n_clases = sum(len(c["clases"]) for c in cat["capas"])
    botones = ['<button type="button" data-capa="todas" aria-pressed="true">Todas</button>']
    secciones = []
    for capa in cat["capas"]:
        cid = capa["id"]
        botones.append(f'<button type="button" data-capa="{e(cid)}" aria-pressed="false">'
                       f'{e("TX" if cid == "TX" else cid)}</button>')
        filas = []
        for c in capa["clases"]:
            cwes = "<br>".join(
                a(cwe[x]["url"], x) + f' <span class="n">{e(nombre_corto(cwe[x]["titulo"], x))}</span>'
                + (f' <span class="aviso" title="Uso de mapeo en MITRE">{e(cwe[x]["uso_mapeo"])}</span>'
                   if cwe[x].get("uso_mapeo") in ("DISCOURAGED", "PROHIBITED") else "")
                for x in c["cwe"])
            atts = "<br>".join(
                a(att[x]["url"], x) + f' <span class="n">{e(nombre_corto(att[x]["titulo"], x))}</span>'
                for x in c["attack"])
            prots = ", ".join(
                f'<span title="Capa {e(str(smc[p]["capa_osi"]))} en SMC">{e(p)}</span>' for p in c["protocolos"]
            ) or '<span class="n">(general)</span>'
            ctrl = "<ul>" + "".join(f"<li>{e(x)}</li>" for x in c["controles"]) + "</ul>"
            det = "<ul>" + "".join(f"<li>{e(x)}</li>" for x in c["deteccion"]) + "</ul>"
            norma = " ".join(f'<code>{e(x)}</code>' for x in c["ens"] + c["nis2"])
            busq = " · ".join(a(u, NOMBRES_CONSULTA[k]) for k, u in c["consulta"].items())
            filas.append(
                f'<tr id="{e(c["id"])}"><td><strong>{e(c["nombre"])}</strong><br>'
                f'<span class="n">{e(c["descripcion"])}</span><br><code class="id">{e(c["id"])}</code></td>'
                f"<td>{cwes}</td><td>{atts}</td><td>{prots}</td><td>{ctrl}</td><td>{det}</td>"
                f"<td>{norma}</td><td>{busq}</td></tr>")
        secciones.append(
            f'<section class="capa" data-capa="{e(cid)}" id="capa-{e(cid)}">'
            f"<h2>{e(etiqueta_capa(capa))}</h2><p>{e(capa['descripcion'])}</p>"
            f'<p class="activos"><strong>Activos on-prem típicos:</strong> {e(", ".join(capa["activos"]))}</p>'
            '<div class="tabla"><table><thead><tr><th>Clase</th><th>CWE</th><th>ATT&amp;CK</th>'
            "<th>Protocolos (SMC)</th><th>Controles on-prem</th><th>Detección</th><th>ENS y NIS2</th>"
            f"<th>Buscar CVE</th></tr></thead><tbody>{''.join(filas)}</tbody></table></div></section>")
    fuentes = "".join(
        f"<li>{a(f['url'], f['nombre'])} <span class=\"n\">({e(f['organismo'])}). {e(f['uso'])}"
        + (" Abrir a mano: bloquea clientes automáticos." if f["verificacion"] == "manual" else "")
        + "</span></li>" for f in fue["fuentes"])
    hermanos = " · ".join(a(u, t) for t, u in ENLACES_HERMANOS)
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vulnerabilidades y protecciones por capa OSI</title>
<meta name="description" content="Catálogo de vulnerabilidades y protecciones on-premise por capa OSI con CWE, MITRE ATT&amp;CK, ENS y NIS2.">
<style>
:root{{--bg:#0d1117;--panel:#161b22;--line:#30363d;--txt:#e6edf3;--mut:#8b949e;--acc:#ef233c;--lnk:#79c0ff}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--txt);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}}
header,main,footer{{max-width:1500px;margin:0 auto;padding:0 20px}}
header{{padding-top:28px;padding-bottom:8px;border-bottom:1px solid var(--line)}}
h1{{font-size:1.7rem;margin:0 0 6px}} h1 span{{color:var(--acc)}}
h2{{font-size:1.25rem;margin:28px 0 4px;border-left:4px solid var(--acc);padding-left:10px}}
p{{margin:6px 0}} a{{color:var(--lnk)}} .n{{color:var(--mut)}}
.resumen{{color:var(--mut)}}
nav.filtro{{position:sticky;top:0;background:var(--bg);padding:10px 0;z-index:2;display:flex;flex-wrap:wrap;gap:6px;align-items:center}}
nav.filtro button{{background:var(--panel);color:var(--txt);border:1px solid var(--line);border-radius:6px;padding:5px 12px;cursor:pointer;font:inherit}}
nav.filtro button[aria-pressed="true"]{{border-color:var(--acc);background:#2a1216}}
.tabla{{overflow-x:auto;border:1px solid var(--line);border-radius:8px;background:var(--panel)}}
table{{border-collapse:collapse;width:100%;min-width:1200px;font-size:.88rem}}
th,td{{text-align:left;vertical-align:top;padding:8px 10px;border-bottom:1px solid var(--line)}}
th{{background:#1c2128;position:sticky;top:0;font-weight:600}}
td ul{{margin:0;padding-left:16px}} code{{background:#21262d;border-radius:4px;padding:0 4px;font-size:.82rem;white-space:nowrap;display:inline-block;margin:1px 0}}
code.id{{color:var(--mut)}} .aviso{{color:#d29922;font-size:.75rem}}
.activos{{color:var(--mut)}} footer{{margin-top:36px;padding-bottom:40px;border-top:1px solid var(--line);color:var(--mut)}}
.oculta{{display:none}}
</style>
</head>
<body>
<header>
<h1>Vulnerabilidades y protecciones por capa <span>OSI</span></h1>
<p class="resumen">{len(cat["capas"]) - 1} capas y una sección transversal, {n_clases} clases de ataque con CWE, MITRE ATT&amp;CK, controles on-premise, detección y mapeo a ENS (RD 311/2022) y NIS2 art. 21.2. Sin CVE concretos: cada clase enlaza búsquedas en fuentes oficiales.</p>
<p>Relacionado: {hermanos}</p>
</header>
<main>
<nav class="filtro" aria-label="Filtrar por capa"><span class="n">Capa:</span> {"".join(botones)}</nav>
{"".join(secciones)}
<section id="fuentes"><h2>Fuentes</h2><ul>{fuentes}</ul>
<p class="n">Ids CWE y ATT&amp;CK comprobados contra cwe.mitre.org y attack.mitre.org el {e(str(ver["comprobado"]))}. Mapeo orientativo: juicio inicial, sin auditoría externa. No sustituye el análisis de riesgos de cada sistema.</p></section>
</main>
<footer><p>David Moya · licencia MIT · generado con tools/generar.py desde data/capas.yaml</p></footer>
<script>
(function () {{
  var botones = document.querySelectorAll("nav.filtro button");
  var capas = document.querySelectorAll("section.capa");
  function aplicar(id) {{
    botones.forEach(function (b) {{ b.setAttribute("aria-pressed", String(b.dataset.capa === id)); }});
    capas.forEach(function (s) {{ s.classList.toggle("oculta", id !== "todas" && s.dataset.capa !== id); }});
  }}
  botones.forEach(function (b) {{ b.addEventListener("click", function () {{ aplicar(b.dataset.capa); }}); }});
}})();
</script>
</body>
</html>
"""


def md_tabla_celda(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def markdown(cat, fue, ver) -> str:
    cwe = {r["id"]: r for r in ver["cwe"]}
    att = {r["id"]: r for r in ver["attack"]}
    out = ["# Vulnerabilidades y protecciones por capa OSI", "",
           "Generado con `tools/generar.py` desde `data/capas.yaml`. No editar a mano.", ""]
    for capa in cat["capas"]:
        out += [f"## {etiqueta_capa(capa)}", "", capa["descripcion"], "",
                f"**Activos on-prem típicos:** {', '.join(capa['activos'])}", ""]
        for c in capa["clases"]:
            out += [f"### {c['nombre']} (`{c['id']}`)", "", c["descripcion"], "",
                    "| Campo | Valor |", "| --- | --- |",
                    "| CWE | " + md_tabla_celda(", ".join(f"[{x}]({cwe[x]['url']})" for x in c["cwe"])) + " |",
                    "| ATT&CK | " + md_tabla_celda(", ".join(f"[{x}]({att[x]['url']})" for x in c["attack"])) + " |",
                    "| Protocolos (SMC) | " + (", ".join(c["protocolos"]) or "(general)") + " |",
                    "| ENS | " + ", ".join(c["ens"]) + " |",
                    "| NIS2 | " + ", ".join(c["nis2"]) + " |",
                    "| Buscar CVE | " + " · ".join(f"[{NOMBRES_CONSULTA[k]}]({u})" for k, u in c["consulta"].items()) + " |",
                    "", "Controles:", ""] + [f"- {x}" for x in c["controles"]] + \
                   ["", "Detección:", ""] + [f"- {x}" for x in c["deteccion"]] + [""]
    out += ["## Fuentes", ""] + [f"- [{f['nombre']}]({f['url']}) ({f['organismo']})" for f in fue["fuentes"]] + [""]
    return "\n".join(out)


def main() -> int:
    # Validate data before generating; generated files are checked afterwards too.
    errores = [x for x in validar_repo() if not x.startswith(("index.html", "capas.md", "README.md"))]
    if errores:
        for x in errores:
            print("ERROR", x)
        return 1
    cat, fue, ver, smc = cargar()
    (RAIZ / "docs").mkdir(exist_ok=True)
    (RAIZ / "docs/index.html").write_text(html_pagina(cat, fue, ver, smc), encoding="utf-8")
    (RAIZ / "docs/capas.md").write_text(markdown(cat, fue, ver), encoding="utf-8")
    print("Generado docs/index.html y docs/capas.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
