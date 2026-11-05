"""Generate docs/historico/ (matrix, filterable table and entry cards) from data/historico.yaml.

All content is rendered to HTML here, so the page works without JavaScript. historico.js only shows and hides
what is already rendered. CSS and JS live in separate files so the page can carry a strict CSP. Every value from
the data is HTML-escaped.
"""
from __future__ import annotations

import html
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
ESTATICOS = Path(__file__).resolve().parent / "historico_estaticos"

AREAS = [
    ("enlace", "Enlace y acceso", "Capa funcional 2"),
    ("red", "Red y encaminamiento", "Capa funcional 3"),
    ("transporte", "Transporte", "Capa funcional 4"),
    ("cripto-sesion", "Protección criptográfica y sesión", "Funciones 5 y 6, mapeo no exclusivo"),
    ("aplicacion", "Aplicación y servicios", "Capa 7, con efectos entre capas"),
]
DECADAS = ["1980", "1990", "2000", "2010", "2020"]
SIN_FECHA = "sin-fecha"
CAUSAS = {"D": "Diseño", "I": "Implementación", "C": "Configuración"}
NATURALEZAS = {
    "P": ("Divulgación pública", "Publicación del trabajo o aviso. Puede diferir del descubrimiento privado."),
    "H": ("Antecedente histórico", "Identificado por otra fuente técnica; no es documento original inspeccionado."),
    "R": ("Documentación de referencia", "Demuestra que el riesgo estaba documentado, no su primer descubrimiento."),
}
CHANGELOG = "https://github.com/pedri77/vulnerabilidades-capas-osi/blob/main/CHANGELOG.md"
REVISOR_IA = "Claude (IA), por delegación de David Moya"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
       "base-uri 'none'; form-action 'none'")
AVISO_VERSION = ("La versión citada es la primera corrección histórica, no una recomendación de instalarla hoy. "
                 "Usa una rama mantenida o un backport confirmado por el proveedor.")

e = html.escape


def publicadas(hist: dict) -> list[dict]:
    return [x for x in hist["entradas"] if x["revision"]["estado"] != "retirada"]


def decada(entrada: dict) -> str:
    """Decade of the earliest dated event, or SIN_FECHA. Never invents a date."""
    if not entrada["fechas"]:
        return SIN_FECHA
    return min(ev["valor"][:4] for ev in entrada["fechas"])[:3] + "0"


def conteo(entradas: list[dict]) -> dict[tuple[str, str], int]:
    out: dict[tuple[str, str], int] = {}
    for x in entradas:
        k = (x["area"], decada(x))
        out[k] = out.get(k, 0) + 1
    return out


def fecha_txt(ev: dict) -> str:
    cota = "≤" if ev.get("cota") == "maxima" else ""
    return f"{cota}{ev['valor']} [{ev['naturaleza']}]"


def fechas_txt(x: dict) -> str:
    return "; ".join(fecha_txt(ev) for ev in x["fechas"]) or "Sin primera fecha fijada"


def tipos_identificador(x: dict) -> list[str]:
    tipos = ["cve" if x["cve"] else "sin-cve"]
    if x["es_familia"]:
        tipos.append("familia")
    return tipos


def naturalezas(x: dict) -> list[str]:
    return sorted({ev["naturaleza"] for ev in x["fechas"]}) or ["sin-fecha"]


def nota_revision(entradas: list[dict]) -> str:
    """State who reviewed the entries, from the data. An AI review must never read as a human one."""
    revisores = sorted({x["revision"]["por"] for x in entradas if x["revision"].get("por")})
    if not revisores:
        return "Entradas sin revisar contra sus fuentes."
    texto = f"Entradas contrastadas con sus fuentes por {', '.join(revisores)}."
    if REVISOR_IA in revisores:
        texto += " Revisión asistida por IA, sin revisión humana entrada a entrada: comprueba la fuente antes de citar."
    return texto


def html_matriz(entradas: list[dict]) -> str:
    n = conteo(entradas)
    cab = "".join(f'<th scope="col">{d}s</th>' for d in DECADAS)
    filas = []
    for aid, nombre, nota in AREAS:
        celdas = []
        for d in DECADAS + [SIN_FECHA]:
            v = n.get((aid, d), 0)
            if v:
                etiqueta = f"{nombre}, {'sin fecha' if d == SIN_FECHA else d + 's'}: {v} entradas"
                nivel = min(4, 1 + v // 3)
                celdas.append(f'<td><a class="celda n{nivel}" href="?area={e(aid)}&amp;decada={e(d)}#tabla" '
                              f'data-area="{e(aid)}" data-decada="{e(d)}" aria-label="{e(etiqueta)}">{v}</a></td>')
            else:
                celdas.append('<td><span class="vacia" aria-label="Sin entradas">0</span></td>')
        total = sum(n.get((aid, d), 0) for d in DECADAS + [SIN_FECHA])
        filas.append(f'<tr><th scope="row">{e(nombre)}<small>{e(nota)}</small></th>{"".join(celdas)}'
                     f'<td class="total">{total}</td></tr>')
    filas.append('<tr class="fisica"><th scope="row">Capa física<small>Amenazas, fuera del inventario</small></th>'
                 '<td colspan="7"><a href="#fisica">Ver amenazas: no se cuentan entre las entradas</a></td></tr>')
    totales = "".join(
        f'<td>{sum(n.get((a[0], d), 0) for a in AREAS)}</td>' for d in DECADAS + [SIN_FECHA])
    return (f'<div class="desplaza" tabindex="0" role="region" aria-label="Matriz de entradas por área y década">'
            f'<table class="matriz"><caption>Entradas documentadas por área funcional y década</caption>'
            f'<thead><tr><th scope="col">Área</th>{cab}<th scope="col">Sin fecha</th><th scope="col">Total</th></tr></thead>'
            f'<tbody>{"".join(filas)}</tbody>'
            f'<tfoot><tr><th scope="row">Total</th>{totales}<td class="total">{len(entradas)}</td></tr></tfoot>'
            f'</table></div>')


def enlace_fuente(sid: str, fuentes: dict) -> str:
    f = fuentes[sid]
    return f'<a href="{e(f["url"])}" rel="noopener">{e(sid)}</a> <span class="n">{e(f["titulo"])}</span>'


def html_entrada(x: dict, fuentes: dict) -> str:
    area = next(a[1] for a in AREAS if a[0] == x["area"])
    causas = ", ".join(CAUSAS[c] for c in x["causas"])
    datos = {
        "area": x["area"], "decada": decada(x), "causa": " ".join(x["causas"]),
        "naturaleza": " ".join(naturalezas(x)), "ident": " ".join(tipos_identificador(x)),
    }
    attrs = " ".join(f'data-{k}="{e(v)}"' for k, v in datos.items())
    busca = " ".join([x["id"], x["titulo"], x["protocolo"], x["alcance"], x["hallazgo"], x["identificador"]]).lower()
    filas = [("Alcance", e(x["alcance"])), ("Hallazgo", e(x["hallazgo"])), ("Causa", e(causas)),
             ("Fecha", e(fechas_txt(x))), ("Identificador", e(x["identificador"])),
             ("Condición", e(x["condicion"]))]
    if x["impacto"]:
        filas.append(("Impacto posible", e(x["impacto"])))
    filas.append(("Corrección o control", e(x["control"])))
    if x["cve"]:
        filas.append(("Registro CVE", " ".join(
            f'<a href="https://www.cve.org/CVERecord?id={e(c)}" rel="noopener">{e(c)}</a>' for c in x["cve"])))
    if x["clases"]:
        filas.append(("Clases del catálogo", " ".join(f'<a href="../#{e(k)}"><code>{e(k)}</code></a>' for k in x["clases"])))
    filas.append(("Fuentes", "<br>".join(enlace_fuente(s, fuentes) for s in x["fuentes"])))
    dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in filas)
    aviso = f'<p class="aviso">{e(AVISO_VERSION)}</p>' if x["aviso_version"] else ""
    marca = '<span class="marca">familia</span>' if x["es_familia"] else ""
    return (f'<details class="entrada" id="{e(x["id"])}" {attrs} data-busca="{e(busca)}">'
            f'<summary><code>{e(x["id"])}</code><strong>{e(x["titulo"])}</strong>{marca}'
            f'<span class="prot">{e(x["protocolo"])}</span><span class="fecha">{e(fechas_txt(x))}</span>'
            f'<span class="area">{e(area)}</span></summary>'
            f'<div class="ficha"><dl>{dl}</dl>{aviso}<p><a href="#{e(x["id"])}">Enlace a esta entrada</a></p></div></details>')


def html_filtros() -> str:
    def grupo(nombre: str, opciones: list[tuple[str, str]]) -> str:
        ops = "".join(f'<option value="{e(v)}">{e(t)}</option>' for v, t in opciones)
        return f'<select name="{e(nombre)}"><option value="">Todas</option>{ops}</select>'

    return ('<form class="filtros" id="filtros" hidden aria-label="Filtrar entradas">'
            f'<label>Área {grupo("area", [(a[0], a[1]) for a in AREAS])}</label>'
            f'<label>Década {grupo("decada", [(d, d + "s") for d in DECADAS] + [(SIN_FECHA, "Sin fecha")])}</label>'
            f'<label>Causa {grupo("causa", list(CAUSAS.items()))}</label>'
            f'<label>Fecha {grupo("naturaleza", [(k, v[0]) for k, v in NATURALEZAS.items()] + [("sin-fecha", "Sin primera fecha")])}</label>'
            f'<label>Identificador {grupo("ident", [("cve", "Con CVE"), ("sin-cve", "Sin CVE citado"), ("familia", "Familia")])}</label>'
            '<label class="texto">Texto <input type="search" name="q" placeholder="TLS, Heartbleed, CVE-2014..."></label>'
            '<button type="button" id="limpiar">Limpiar</button></form>'
            '<p id="estado" class="n" role="status" aria-live="polite"></p>'
            '<p id="vacio" class="aviso" hidden>Ninguna entrada cumple estos filtros. '
            '<button type="button" id="limpiar2">Limpiar filtros</button></p>')


def html_pagina(hist: dict, fue: dict, ver: dict) -> str:
    entradas = publicadas(hist)
    fuentes = {f["id"]: f for f in fue["fuentes"]}
    meta = hist["meta"]
    anios = sorted(ev["valor"][:4] for x in entradas for ev in x["fechas"])
    leyenda = "".join(f"<dt>[{k}] {e(v[0])}</dt><dd>{e(v[1])}</dd>" for k, v in NATURALEZAS.items())
    fisica = "".join(
        f'<tr><th scope="row">{e(f["superficie"])}</th><td>{e(f["amenaza"])}</td><td>{e(f["evidencia"])}</td><td>{e(f["control"])}</td></tr>'
        for f in hist["capa_fisica"])
    lista = "".join(html_entrada(x, fuentes) for x in entradas)
    refs = "".join(
        f'<li id="{e(f["id"])}"><a href="{e(f["url"])}" rel="noopener">{e(f["id"])}: {e(f["titulo"])}</a> '
        f'<span class="n">{e(f["respalda"])}{" Fuente de contexto." if f["uso"] == "contexto" else ""}</span></li>'
        for f in fue["fuentes"])
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{e(CSP)}">
<title>Matriz histórica de vulnerabilidades de protocolos OSI</title>
<meta name="description" content="{len(entradas)} entradas históricas de vulnerabilidades y debilidades de protocolos por área OSI y década, con fecha, causa, control y fuente.">
<link rel="stylesheet" href="historico.css">
</head>
<body>
<header>
<p class="migas"><a href="../">Catálogo por capa OSI</a> / Histórico</p>
<h1>Matriz histórica de vulnerabilidades de <span>protocolos OSI</span></h1>
<p class="resumen">{len(entradas)} entradas desde {anios[0]} hasta {anios[-1]}, cada una con fecha, causa, condición, control y fuente. Edición {e(meta["edicion"])} (<a href="{CHANGELOG}">registro de cambios</a>), fuentes consultadas el {e(meta["fecha_consulta"])}.</p>
<ul class="limites" aria-label="Límites de esta edición">
<li><strong>No es un censo.</strong> Es una selección documentada y ampliable.</li>
<li><strong>Sin revisión sistemática de 2026.</strong> Los casos llegan a {anios[-1]}.</li>
<li><strong>Una entrada no equivale a un CVE.</strong> Puede ser un fallo, una familia o una debilidad de diseño: no se suman como CVE.</li>
<li><strong>No acredita exposición.</strong> Sin pruebas de explotación ni datos de ningún activo.</li>
<li><strong>Revisión.</strong> {e(nota_revision(entradas))}</li>
</ul>
</header>
<main>
<section id="matriz"><h2>Matriz por área y década</h2>
{html_matriz(entradas)}
<p class="n">Refleja lo documentado en esta edición, no todo lo ocurrido: más entradas en una década no significa más vulnerabilidades reales. La capa es una clasificación funcional, no una asignación normativa: TLS no corresponde solo a las capas 5 o 6, y DHCP y BGP funcionan sobre otros protocolos. Cada entrada se cuenta en la década de su fecha más antigua.</p>
</section>
<section id="tabla"><h2>Entradas</h2>
{html_filtros()}
<div id="lista">{lista}</div>
<details class="leyenda"><summary>Cómo leer las fechas y las causas</summary><dl>{leyenda}
<dt>≤ fecha</dt><dd>Existencia documentada como máximo en esa fecha.</dd>
<dt>Sin primera fecha fijada</dt><dd>Hay fuente técnica, sin establecer prioridad histórica.</dd>
<dt>Año del CVE</dt><dd>No equivale al año de divulgación: Ping o' Death lleva CVE-1999-0128 con antecedente de 1996.</dd>
<dt>Causas</dt><dd>Diseño, implementación y configuración. Las combinaciones indican interacción y no son clasificación oficial del emisor del CVE.</dd></dl></details>
</section>
<section id="fisica"><h2>Capa física: amenazas</h2>
<p>No se cuentan entre las entradas ni llevan CVE o fecha de descubrimiento. La desautenticación Wi-Fi es capa 2 y no debe confundirse con interferencia de radio.</p>
<div class="desplaza" tabindex="0" role="region" aria-label="Amenazas de capa física"><table><thead><tr><th scope="col">Superficie</th><th scope="col">Amenaza</th><th scope="col">Evidencia que pedir</th><th scope="col">Control propuesto</th></tr></thead><tbody>{fisica}</tbody></table></div>
</section>
<section id="fuentes"><h2>Fuentes</h2><ol class="refs">{refs}</ol>
<p class="n">CVE comprobados contra el registro oficial el {e(str(ver["comprobado"]))}. Las fuentes históricas pueden contener recomendaciones obsoletas. Corregir una vulnerabilidad no acredita por sí solo cumplimiento de ENS, NIS2 o ISO 27001.</p></section>
</main>
<footer><p>David Moya · licencia MIT · generado con tools/generar.py desde data/historico.yaml</p></footer>
<script src="historico.js"></script>
</body>
</html>
"""


def escribir(hist: dict, fue: dict, ver: dict, destino: Path | None = None) -> None:
    d = destino or RAIZ / "docs/historico"
    d.mkdir(parents=True, exist_ok=True)
    (d / "index.html").write_text(html_pagina(hist, fue, ver), encoding="utf-8")
    for nombre in ("historico.css", "historico.js"):
        (d / nombre).write_text((ESTATICOS / nombre).read_text(encoding="utf-8"), encoding="utf-8")
