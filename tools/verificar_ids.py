"""Check every CWE, ATT&CK and CVE id (and optionally every URL) of the catalogue against the official sites.

Writes data/verificacion_ids.yaml with the HTTP status, the page title and a state per id:
  ok          200 and the page is not deprecated or revoked
  obsoleto    200 but the page says deprecated or revoked
  movido      ATT&CK page is only a redirect to a new id (destino)
  fallo       anything else
CWE entries also record MITRE's "Vulnerability Mapping" usage (ALLOWED, ALLOWED-WITH-REVIEW, DISCOURAGED,
PROHIBITED) when the page shows it.

Usage: python tools/verificar_ids.py [--urls]
Needs network. Stdlib + PyYAML.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parent.parent
UA = "Mozilla/5.0 (verificador vulnerabilidades-capas-osi)"
# Never checked automatically, listed as manual: anti-bot firewalls (403 to scripts, www.cisa.gov after a burst)
# and www.isg.rhul.ac.uk, whose incomplete certificate chain fails in urllib but not in browsers.
HOSTS_MANUALES = ("www.cvedetails.com", "www.ccn-cert.cni.es", "ccn-cert.cni.es", "eur-lex.europa.eu", "www.cisco.com",
                  "www.cisa.gov", "www.isg.rhul.ac.uk")


def url_cwe(cid: str) -> str:
    return f"https://cwe.mitre.org/data/definitions/{cid.split('-')[1]}.html"


def url_attack(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def descargar(url: str) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:  # noqa: BLE001 - network errors are reported, not raised
        return 0, str(e)


def titulo(texto: str) -> str:
    m = re.search(r"<title>(.*?)</title>", texto, re.S | re.I)
    return html.unescape(re.sub(r"\s+", " ", m.group(1))).strip() if m else ""


def comprobar_cwe(cid: str) -> dict:
    url = url_cwe(cid)
    st, txt = descargar(url)
    t = titulo(txt)
    res = {"id": cid, "url": url, "http": st, "titulo": t}
    if st == 200 and cid in t:
        obsoleto = "DEPRECATED" in t.upper()
        res["estado"] = "obsoleto" if obsoleto else "ok"
        plano = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", txt))
        m = re.search(r"Vulnerability Mapping Notes.*? Usage ([A-Z][A-Z-]+)", plano)
        if m:
            res["uso_mapeo"] = m.group(1)
    else:
        res["estado"] = "fallo"
    return res


def comprobar_attack(tid: str) -> dict:
    url = url_attack(tid)
    st, txt = descargar(url)
    t = titulo(txt)
    res = {"id": tid, "url": url, "http": st, "titulo": t}
    low = txt.lower()
    movido = re.search(r'http-equiv="refresh" content="0; url=/techniques/([^"]+)"', txt)
    if movido:
        # ATT&CK keeps old ids as a redirect to the new technique: report it, do not accept it.
        res["estado"] = "movido"
        res["destino"] = "T" + movido.group(1).lstrip("T").replace("/", ".").rstrip(".")
        return res
    if st == 200 and t and "page not found" not in t.lower():
        obsoleto = ("has been deprecated" in low) or ("has been revoked" in low) or ("revoked by" in low)
        # The page must name the technique id it was asked for.
        nombrado = tid in txt
        res["estado"] = "obsoleto" if obsoleto else ("ok" if nombrado else "fallo")
    else:
        res["estado"] = "fallo"
    return res


def comprobar_cve(cid: str) -> dict:
    """ok only if the official CVE record exists and is PUBLISHED (REJECTED records fail)."""
    url = f"https://www.cve.org/CVERecord?id={cid}"
    st, txt = descargar(f"https://cveawg.mitre.org/api/cve/{cid}")
    res = {"id": cid, "url": url, "http": st, "estado": "fallo"}
    if st == 200:
        try:
            meta = json.loads(txt).get("cveMetadata", {})
        except ValueError:
            return res
        res["publicado"] = (meta.get("datePublished") or "")[:10]
        if meta.get("cveId") == cid and meta.get("state") == "PUBLISHED":
            res["estado"] = "ok"
    return res


def avisos_fecha(entradas: list[dict], r_cve: list[dict]) -> list[str]:
    """Warn when the CVE record date differs in year from the entry's public date. Informative only:
    a CVE id can be assigned long after disclosure (CVE-1999-0128)."""
    publicado = {r["id"]: r.get("publicado", "") for r in r_cve}
    out = []
    for x in entradas:
        anios = {ev["valor"][:4] for ev in x["fechas"] if ev["naturaleza"] == "P"}
        for c in x["cve"]:
            if anios and publicado.get(c) and publicado[c][:4] not in anios:
                out.append(f"{x['id']}: {c} publicado {publicado[c]}, entrada {sorted(anios)}")
    return out


def comprobar_url(url: str) -> dict:
    host = re.sub(r"^https://([^/]+)/?.*$", r"\1", url)
    if host in HOSTS_MANUALES:
        return {"url": url, "http": None, "estado": "manual"}
    st, _ = descargar(url)
    return {"url": url, "http": st, "estado": "ok" if st == 200 else "fallo"}


def recoger(catalogo: dict) -> tuple[list[str], list[str], list[str]]:
    cwes, tecs, urls = set(), set(), set()
    for capa in catalogo["capas"]:
        for c in capa["clases"]:
            cwes.update(c["cwe"])
            tecs.update(c["attack"])
            urls.update(c["consulta"].values())
    return sorted(cwes, key=lambda x: int(x.split("-")[1])), sorted(tecs), sorted(urls)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--urls", action="store_true", help="also check every search and source URL")
    a = ap.parse_args(argv)
    catalogo = yaml.safe_load((RAIZ / "data/capas.yaml").read_text(encoding="utf-8"))
    fuentes = yaml.safe_load((RAIZ / "data/fuentes.yaml").read_text(encoding="utf-8"))
    hist = yaml.safe_load((RAIZ / "data/historico.yaml").read_text(encoding="utf-8"))
    fue_hist = yaml.safe_load((RAIZ / "data/historico_fuentes.yaml").read_text(encoding="utf-8"))
    cwes, tecs, urls = recoger(catalogo)
    cves = sorted({c for x in hist["entradas"] for c in x["cve"]})
    with ThreadPoolExecutor(max_workers=6) as ex:
        r_cwe = list(ex.map(comprobar_cwe, cwes))
        r_att = list(ex.map(comprobar_attack, tecs))
        r_cve = list(ex.map(comprobar_cve, cves))
        r_url = []
        if a.urls:
            todas = sorted(set(urls) | {f["url"] for f in fuentes["fuentes"] + fue_hist["fuentes"]})
            r_url = list(ex.map(comprobar_url, todas))
    salida = {
        "comprobado": dt.date.today().isoformat(),
        "nota": "Generado por tools/verificar_ids.py; no editar a mano.",
        "cwe": r_cwe,
        "attack": r_att,
        "cve": r_cve,
    }
    if a.urls:
        salida["urls"] = r_url
    (RAIZ / "data/verificacion_ids.yaml").write_text(
        yaml.safe_dump(salida, allow_unicode=True, sort_keys=False, width=200), encoding="utf-8"
    )
    malos = [r for r in r_cwe + r_att + r_cve + r_url if r["estado"] in ("fallo", "obsoleto", "movido")]
    print(f"CWE {sum(r['estado'] == 'ok' for r in r_cwe)}/{len(r_cwe)} ok; "
          f"ATT&CK {sum(r['estado'] == 'ok' for r in r_att)}/{len(r_att)} ok; "
          f"CVE {sum(r['estado'] == 'ok' for r in r_cve)}/{len(r_cve)} ok"
          + (f"; URL {sum(r['estado'] == 'ok' for r in r_url)}/{len(r_url)} ok, "
             f"{sum(r['estado'] == 'manual' for r in r_url)} manuales" if a.urls else ""))
    for r in malos:
        print("  ", r["estado"].upper(), r.get("id", ""), r["url"], r.get("http"), r.get("titulo", ""), r.get("destino", ""))
    for aviso in avisos_fecha(hist["entradas"], r_cve):
        print("   AVISO fecha", aviso)
    return 1 if malos else 0


if __name__ == "__main__":
    sys.exit(main())
