"""Validate the catalogue: schema, id formats, ENS ids, protocol ids, https-only links and the pedri77 allowlist.

Usage: python tools/validar.py        (exit 0 if valid, 1 otherwise)
Stdlib + PyYAML. No network: online checks live in tools/verificar_ids.py.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parent.parent

RE_CWE = re.compile(r"^CWE-\d+$")
RE_ATTACK = re.compile(r"^T\d{4}(\.\d{3})?$")
RE_NIS2 = re.compile(r"^NIS2-21\.2\.[a-j]$")
RE_CLASE = re.compile(r"^(L[1-7]|TX)-[A-Z0-9]+(-[A-Z0-9]+)*$")
RE_URL = re.compile(r"""(?:https?|ftp)://[^\s"'<>)\]]+""")

CAPAS_ESPERADAS = ["L1", "L2", "L3", "L4", "L5", "L6", "L7", "TX"]
CAMPOS_CAPA = ("id", "numero", "nombre", "descripcion", "activos", "clases")
CAMPOS_CLASE = ("id", "nombre", "descripcion", "cwe", "attack", "protocolos", "controles",
                "deteccion", "ens", "nis2", "palabra_clave", "consulta")
PLANTILLAS_CONSULTA = {
    "nvd": "https://nvd.nist.gov/vuln/search?keyword={k}&resultType=records",
    "euvd": "https://euvd.enisa.europa.eu/search?text={k}",
    "cisa_kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={k}",
    "cvedetails": "https://www.cvedetails.com/google-search-results.php?q={k}",
}
# Public pedri77 repos that may be linked (GitHub repo or its Pages site). Anything else is refused.
REPOS_PERMITIDOS = frozenset({
    "Basicos_Proteccion_Capas_OSI", "modelo_OSI", "security-manager-control", "smc-cinematica",
    "edr-visual-app", "sase-visual-app", "Basic_Firewalls", "ics-security-studio", "wafforge",
    "kev_dash_project", "threat-intelligence-feeds",
})
# Ours: the repo itself, once published, may link to its own Pages site.
REPOS_PERMITIDOS_PROPIOS = frozenset({"vulnerabilidades-capas-osi"})


def leer_lista_ens(texto: str) -> set[str]:
    return {ln.strip() for ln in texto.splitlines() if ln.strip() and not ln.startswith("#")}


def comprobar_url(url: str, donde: str) -> list[str]:
    errores = []
    if not url.startswith("https://"):
        errores.append(f"{donde}: URL no https: {url}")
    m = re.match(r"^https?://(?:www\.)?github\.com/pedri77/([^/?#]+)", url, re.I) or \
        re.match(r"^https?://pedri77\.github\.io/([^/?#]+)", url, re.I)
    if m:
        repo = m.group(1).removesuffix(".git")
        if repo not in REPOS_PERMITIDOS | REPOS_PERMITIDOS_PROPIOS:
            errores.append(f"{donde}: enlace a repo de pedri77 fuera de la lista blanca: {url}")
    elif re.search(r"pedri77", url, re.I) and "users.noreply.github.com" not in url:
        errores.append(f"{donde}: enlace a pedri77 con forma desconocida: {url}")
    return errores


def textos(obj, ruta="raiz"):
    """Yield (path, string) for every string inside obj."""
    if isinstance(obj, str):
        yield ruta, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from textos(v, f"{ruta}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from textos(v, f"{ruta}[{i}]")


def comprobar_texto(ruta: str, s: str) -> list[str]:
    errores = []
    if "—" in s or "–" in s:
        errores.append(f"{ruta}: guion largo o semilargo como puntuación")
    sin_urls = RE_URL.sub("", s)
    if "--" in sin_urls:
        errores.append(f"{ruta}: '--' como puntuación")
    for url in RE_URL.findall(s):
        errores.extend(comprobar_url(url.rstrip(".,;:"), ruta))
    return errores


def _lista(clase: dict, campo: str, minimo: int, donde: str) -> list:
    v = clase.get(campo)
    if not isinstance(v, list) or len(v) < minimo or not all(isinstance(x, str) and x.strip() for x in v):
        raise ValueError(f"{donde}.{campo}: lista de textos con al menos {minimo} elemento(s)")
    if len(set(v)) != len(v):
        raise ValueError(f"{donde}.{campo}: elementos repetidos")
    return v


def validar_catalogo(catalogo: dict, ens_ids: set[str], protocolos: set[str],
                     verificacion: dict | None = None) -> list[str]:
    errores: list[str] = []
    if not isinstance(catalogo, dict) or catalogo.get("version") != "v1" or not isinstance(catalogo.get("capas"), list):
        return ["capas.yaml: falta version v1 o la lista capas"]
    ids_capa = [c.get("id") for c in catalogo["capas"] if isinstance(c, dict)]
    if ids_capa != CAPAS_ESPERADAS:
        errores.append(f"capas.yaml: capas esperadas {CAPAS_ESPERADAS}, encontradas {ids_capa}")
    vistos: set[str] = set()
    ok_cwe = ok_att = None
    if verificacion is not None:
        ok_cwe = {r["id"] for r in verificacion.get("cwe", []) if r.get("estado") == "ok"}
        ok_att = {r["id"] for r in verificacion.get("attack", []) if r.get("estado") == "ok"}
    for capa in catalogo["capas"]:
        if not isinstance(capa, dict):
            errores.append("capas.yaml: capa que no es un mapa")
            continue
        cid = capa.get("id", "?")
        faltan = [k for k in CAMPOS_CAPA if k not in capa]
        if faltan:
            errores.append(f"{cid}: faltan campos {faltan}")
            continue
        esperado = None if cid == "TX" else int(cid[1:]) if cid in CAPAS_ESPERADAS else -1
        if capa["numero"] != esperado:
            errores.append(f"{cid}: numero debe ser {esperado}")
        if not isinstance(capa["activos"], list) or len(capa["activos"]) < 2:
            errores.append(f"{cid}: activos necesita al menos 2 elementos")
        if not isinstance(capa["clases"], list) or not capa["clases"]:
            errores.append(f"{cid}: sin clases")
            continue
        for clase in capa["clases"]:
            if not isinstance(clase, dict):
                errores.append(f"{cid}: clase que no es un mapa")
                continue
            kid = clase.get("id", "?")
            donde = f"{cid}/{kid}"
            extra = set(clase) - set(CAMPOS_CLASE)
            faltan = [k for k in CAMPOS_CLASE if k not in clase]
            if faltan or extra:
                errores.append(f"{donde}: faltan {faltan} o sobran {sorted(extra)}")
                continue
            if not RE_CLASE.match(kid) or not kid.startswith(cid + "-"):
                errores.append(f"{donde}: id de clase con forma incorrecta (debe empezar por {cid}-)")
            if kid in vistos:
                errores.append(f"{donde}: id de clase repetido")
            vistos.add(kid)
            try:
                cwe = _lista(clase, "cwe", 1, donde)
                att = _lista(clase, "attack", 1, donde)
                prot = _lista(clase, "protocolos", 0, donde)
                _lista(clase, "controles", 2, donde)
                _lista(clase, "deteccion", 1, donde)
                ens = _lista(clase, "ens", 1, donde)
                nis2 = _lista(clase, "nis2", 1, donde)
            except ValueError as e:
                errores.append(str(e))
                continue
            errores += [f"{donde}: CWE mal formado: {x}" for x in cwe if not RE_CWE.match(x)]
            errores += [f"{donde}: técnica ATT&CK mal formada: {x}" for x in att if not RE_ATTACK.match(x)]
            errores += [f"{donde}: medida ENS inexistente en data/ens_ids.txt: {x}" for x in ens if x not in ens_ids]
            errores += [f"{donde}: NIS2 mal formado (NIS2-21.2.a a j): {x}" for x in nis2 if not RE_NIS2.match(x)]
            errores += [f"{donde}: protocolo desconocido en SMC: {x}" for x in prot if x not in protocolos]
            if ok_cwe is not None:
                errores += [f"{donde}: {x} sin verificar en data/verificacion_ids.yaml" for x in cwe if x not in ok_cwe]
                errores += [f"{donde}: {x} sin verificar en data/verificacion_ids.yaml" for x in att if x not in ok_att]
            k = clase["palabra_clave"]
            if not isinstance(k, str) or not re.fullmatch(r"[A-Za-z0-9%.\-]+", k):
                errores.append(f"{donde}: palabra_clave debe ir codificada para URL (espacios como %20)")
            cons = clase["consulta"]
            if not isinstance(cons, dict) or set(cons) != set(PLANTILLAS_CONSULTA):
                errores.append(f"{donde}: consulta debe tener {sorted(PLANTILLAS_CONSULTA)}")
            else:
                for f, plantilla in PLANTILLAS_CONSULTA.items():
                    if cons[f] != plantilla.format(k=k):
                        errores.append(f"{donde}: consulta.{f} no corresponde a palabra_clave")
    for ruta, s in textos(catalogo, "capas.yaml"):
        errores += comprobar_texto(ruta, s)
    return errores


def validar_fuentes(fuentes: dict) -> list[str]:
    errores = []
    lista = fuentes.get("fuentes") if isinstance(fuentes, dict) else None
    if not isinstance(lista, list) or not lista:
        return ["fuentes.yaml: falta la lista fuentes"]
    ids = set()
    for f in lista:
        fid = f.get("id", "?")
        for k in ("id", "nombre", "organismo", "url", "tipo", "uso", "verificacion"):
            if not isinstance(f.get(k), str) or not f[k].strip():
                errores.append(f"fuentes/{fid}: falta {k}")
        if f.get("verificacion") not in ("auto", "manual"):
            errores.append(f"fuentes/{fid}: verificacion debe ser auto o manual")
        if fid in ids:
            errores.append(f"fuentes/{fid}: id repetido")
        ids.add(fid)
    for ruta, s in textos(fuentes, "fuentes.yaml"):
        errores += comprobar_texto(ruta, s)
    return errores


def validar_ficheros_texto(rutas: list[Path]) -> list[str]:
    """Generated pages and README: https only, allowlist, no em dash."""
    errores = []
    for p in rutas:
        if not p.exists():
            continue
        t = p.read_text(encoding="utf-8")
        for url in set(RE_URL.findall(t)):
            url = url.rstrip(".,;:")
            if url.startswith("http://www.w3.org/2000/svg"):
                continue
            errores += comprobar_url(url, p.name)
        if "—" in t:
            errores.append(f"{p.name}: guion largo")
    return errores


def validar_repo(raiz: Path = RAIZ) -> list[str]:
    d = raiz / "data"
    catalogo = yaml.safe_load((d / "capas.yaml").read_text(encoding="utf-8"))
    fuentes = yaml.safe_load((d / "fuentes.yaml").read_text(encoding="utf-8"))
    ens_ids = leer_lista_ens((d / "ens_ids.txt").read_text(encoding="utf-8"))
    smc = yaml.safe_load((d / "smc_protocolos.yaml").read_text(encoding="utf-8"))
    protocolos = {p["id"] for p in smc["protocolos"]}
    verif_p = d / "verificacion_ids.yaml"
    verificacion = yaml.safe_load(verif_p.read_text(encoding="utf-8")) if verif_p.exists() else None
    errores = validar_catalogo(catalogo, ens_ids, protocolos, verificacion)
    if verificacion is None:
        errores.append("data/verificacion_ids.yaml no existe: ejecutar tools/verificar_ids.py")
    errores += validar_fuentes(fuentes)
    errores += validar_ficheros_texto([raiz / "README.md", raiz / "docs/index.html", raiz / "docs/capas.md"])
    return errores


def main() -> int:
    errores = validar_repo()
    for e in errores:
        print("ERROR", e)
    if not errores:
        print("OK: catálogo válido")
    return 1 if errores else 0


if __name__ == "__main__":
    sys.exit(main())
