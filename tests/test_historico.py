"""Tests for the historical matrix: validation rules, generation and CVE verification (unittest; runs under pytest)."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from unittest import mock

import yaml

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "tools"))

import generar  # noqa: E402
import generar_historico as gh  # noqa: E402
import validar  # noqa: E402
import verificar_ids  # noqa: E402


def cargar():
    d = RAIZ / "data"
    hist = yaml.safe_load((d / "historico.yaml").read_text(encoding="utf-8"))
    fue = yaml.safe_load((d / "historico_fuentes.yaml").read_text(encoding="utf-8"))
    ver = yaml.safe_load((d / "verificacion_ids.yaml").read_text(encoding="utf-8"))
    cat = yaml.safe_load((d / "capas.yaml").read_text(encoding="utf-8"))
    return hist, fue, ver, {k["id"] for c in cat["capas"] for k in c["clases"]}


def entrada(hist, oid):
    return next(x for x in hist["entradas"] if x["id"] == oid)


class TestDatosReales(unittest.TestCase):
    def setUp(self):
        self.hist, self.fue, self.ver, self.clases = cargar()

    def test_valido(self):
        self.assertEqual(validar.validar_fuentes_historico(self.fue), [])
        self.assertEqual(validar.validar_historico(self.hist, self.fue, self.clases, self.ver), [])

    def test_tamano_de_la_edicion(self):
        self.assertEqual(len(self.fue["fuentes"]), 57)
        self.assertLessEqual(len(self.hist["entradas"]), 58)

    def test_edicion_publicable(self):
        self.assertEqual(validar.validar_historico(self.hist, self.fue, self.clases, self.ver, publicar=True), [])

    def test_sin_marca_en_datos_publicos(self):
        texto = (RAIZ / "data/historico.yaml").read_text(encoding="utf-8").lower()
        self.assertNotIn("riskitera", texto)

    def test_todo_cve_verificado(self):
        ok = {r["id"] for r in self.ver["cve"] if r["estado"] == "ok"}
        citados = {c for x in self.hist["entradas"] for c in x["cve"]}
        self.assertTrue(citados)
        self.assertEqual(citados - ok, set())


class TestMutaciones(unittest.TestCase):
    """Each test breaks one field of a copy of the real data and expects a specific error."""

    def setUp(self):
        self.hist, self.fue, self.ver, self.clases = cargar()
        self.h = copy.deepcopy(self.hist)
        self.x = entrada(self.h, "OSI-036")

    def errores(self, publicar=False):
        return validar.validar_historico(self.h, self.fue, self.clases, self.ver, publicar)

    def assertError(self, fragmento, publicar=False):
        errs = self.errores(publicar)
        self.assertTrue(any(fragmento in e for e in errs), f"esperaba '{fragmento}' en {errs}")

    def test_id_mal_formado(self):
        self.x["id"] = "OSI-36"
        self.assertError("id con forma incorrecta")

    def test_id_repetido(self):
        self.x["id"] = "OSI-001"
        self.assertError("id repetido")

    def test_cve_mal_formado(self):
        self.x["cve"].append("CVE-14-160")
        self.assertError("CVE mal formado")

    def test_cve_sin_verificar(self):
        self.x["cve"].append("CVE-2099-99999")
        self.assertError("sin verificar")

    def test_fuente_inexistente(self):
        self.x["fuentes"].append("S99")
        self.assertError("fuente inexistente")

    def test_sin_fuentes(self):
        self.x["fuentes"] = []
        self.assertError("sin fuentes")

    def test_area_desconocida(self):
        self.x["area"] = "sesion"
        self.assertError("área desconocida")

    def test_causa_desconocida(self):
        self.x["causas"] = ["X"]
        self.assertError("causas debe ser")

    def test_capa_fuera_de_rango(self):
        self.x["capas_osi"] = [8]
        self.assertError("capas_osi")

    def test_fecha_no_coincide_con_precision(self):
        self.x["fechas"][0]["precision"] = "mes"
        self.assertError("no coincide con su precisión")

    def test_fecha_convertida_por_yaml(self):
        import datetime
        self.x["fechas"][0]["valor"] = datetime.date(2014, 4, 7)
        self.assertError("no coincide con su precisión")

    def test_fecha_sin_naturaleza(self):
        del self.x["fechas"][0]["naturaleza"]
        self.assertError("sin naturaleza")

    def test_clase_inexistente(self):
        self.x["clases"] = ["L6-NO-EXISTE"]
        self.assertError("clase inexistente")

    def test_revisada_sin_clase_ni_motivo(self):
        self.x["clases"], self.x["motivo_sin_clase"] = [], None
        self.x["revision"] = {"estado": "revisada", "fecha": "2026-11-05", "por": "David Moya"}
        self.assertError("sin clases y sin motivo_sin_clase")

    def test_revisada_sin_revisor(self):
        self.x["revision"] = {"estado": "revisada", "fecha": "2026-11-05"}
        self.assertError("sin fecha o sin revisor")

    def test_estado_desconocido(self):
        self.x["revision"] = {"estado": "ok"}
        self.assertError("estado de revisión desconocido")

    def test_pendiente_bloquea_publicar(self):
        self.x["revision"] = {"estado": "pendiente"}
        self.assertError("no se puede publicar", publicar=True)
        self.assertFalse(any(self.x["id"] in e and "publicar" in e for e in self.errores(publicar=False)))

    def test_guion_largo(self):
        self.x["hallazgo"] += " — variante"
        self.assertError("guion largo")

    def test_fuente_http(self):
        f = copy.deepcopy(self.fue)
        f["fuentes"][0]["url"] = "http://example.org/a"
        self.assertTrue(any("URL no https" in e for e in validar.validar_fuentes_historico(f)))

    # Contraprueba: legitimate edge cases of the source must keep passing.
    def test_contraprueba_casos_legitimos(self):
        sin_fecha = entrada(self.h, "OSI-002")
        self.assertEqual(sin_fecha["fechas"], [])
        self.assertEqual(entrada(self.h, "OSI-001")["cve"], [])
        self.assertTrue(entrada(self.h, "OSI-049")["es_familia"])
        self.assertEqual(len(entrada(self.h, "OSI-021")["fechas"]), 2)
        self.x["clases"], self.x["motivo_sin_clase"] = [], "Sin clase equivalente en el catálogo"
        self.x["revision"] = {"estado": "corregida", "fecha": "2026-11-05", "por": "David Moya"}
        self.assertEqual(self.errores(), [])


class TestGenerar(unittest.TestCase):
    def setUp(self):
        self.hist, self.fue, self.ver, _ = cargar()

    def test_suma_de_celdas_igual_a_entradas(self):
        ent = gh.publicadas(self.hist)
        self.assertEqual(sum(gh.conteo(ent).values()), len(ent))

    def test_sin_fecha_no_se_pierde(self):
        h = copy.deepcopy(self.hist)
        x = entrada(h, "OSI-002")
        self.assertEqual(gh.decada(x), gh.SIN_FECHA)
        self.assertEqual(gh.conteo(gh.publicadas(h)).get(("enlace", gh.SIN_FECHA)), 1)

    def test_decada_usa_fecha_mas_antigua(self):
        self.assertEqual(gh.decada(entrada(self.hist, "OSI-040")), "1990")

    def test_retirada_no_se_publica(self):
        h = copy.deepcopy(self.hist)
        entrada(h, "OSI-036")["revision"] = {"estado": "retirada", "fecha": "2026-11-05", "por": "David Moya"}
        pagina = gh.html_pagina(h, self.fue, self.ver)
        self.assertNotIn('id="OSI-036"', pagina)
        self.assertEqual(sum(gh.conteo(gh.publicadas(h)).values()), len(h["entradas"]) - 1)

    def test_escapa_html(self):
        h = copy.deepcopy(self.hist)
        entrada(h, "OSI-001")["titulo"] = "<script>alert(1)</script>"
        pagina = gh.html_pagina(h, self.fue, self.ver)
        self.assertNotIn("<script>alert(1)</script>", pagina)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", pagina)

    def test_pagina_sin_cdn_con_csp_y_limites(self):
        p = gh.html_pagina(self.hist, self.fue, self.ver)
        self.assertIn("Content-Security-Policy", p)
        self.assertNotIn("<style", p)
        self.assertNotIn("cdn", p.lower())
        for texto in ("No es un censo", "Sin revisión sistemática de 2026", "no equivale a un CVE"):
            self.assertIn(texto, p)
        self.assertNotIn("riskitera", p.lower())

    def test_revision_por_ia_se_declara(self):
        h = copy.deepcopy(self.hist)
        for x in h["entradas"]:
            x["revision"] = {"estado": "revisada", "fecha": "2026-11-05", "por": gh.REVISOR_IA}
        self.assertIn("sin revisión humana entrada a entrada", gh.html_pagina(h, self.fue, self.ver))
        for x in h["entradas"]:
            x["revision"]["por"] = "David Moya"
        self.assertNotIn("sin revisión humana", gh.html_pagina(h, self.fue, self.ver))

    def test_aviso_de_version_antigua(self):
        p = gh.html_pagina(self.hist, self.fue, self.ver)
        self.assertEqual(p.count(gh.e(gh.AVISO_VERSION)), sum(x["aviso_version"] for x in gh.publicadas(self.hist)))

    def test_cada_cve_enlaza_a_su_registro(self):
        p = gh.html_pagina(self.hist, self.fue, self.ver)
        for c in {c for x in gh.publicadas(self.hist) for c in x["cve"]}:
            self.assertIn(f"https://www.cve.org/CVERecord?id={c}", p)

    def test_catalogo_enlaza_casos_y_ficha_enlaza_clase(self):
        h = copy.deepcopy(self.hist)
        x = entrada(h, "OSI-036")
        x["clases"] = ["L6-TLS-DEBIL"]
        cat, fue, ver, smc = generar.cargar()
        self.assertIn('href="historico/#OSI-036"', generar.html_pagina(cat, fue, ver, smc, h))
        self.assertIn('href="../#L6-TLS-DEBIL"', gh.html_pagina(h, self.fue, self.ver))


class TestVerificarCve(unittest.TestCase):
    def respuesta(self, estado, cid="CVE-2014-0160"):
        cuerpo = '{"cveMetadata":{"cveId":"%s","state":"%s","datePublished":"2014-04-07T00:00:00.000Z"}}' % (cid, estado)
        return mock.patch.object(verificar_ids, "descargar", return_value=(200, cuerpo))

    def test_publicado(self):
        with self.respuesta("PUBLISHED"):
            self.assertEqual(verificar_ids.comprobar_cve("CVE-2014-0160")["estado"], "ok")

    def test_rechazado_falla(self):
        with self.respuesta("REJECTED"):
            self.assertEqual(verificar_ids.comprobar_cve("CVE-2014-0160")["estado"], "fallo")

    def test_otro_id_falla(self):
        with self.respuesta("PUBLISHED", "CVE-2000-0001"):
            self.assertEqual(verificar_ids.comprobar_cve("CVE-2014-0160")["estado"], "fallo")

    def test_inexistente_falla(self):
        with mock.patch.object(verificar_ids, "descargar", return_value=(404, "")):
            self.assertEqual(verificar_ids.comprobar_cve("CVE-2099-99999")["estado"], "fallo")

    def test_aviso_de_fecha_distinta(self):
        x = {"id": "OSI-013", "cve": ["CVE-1999-0128"], "fechas": [{"valor": "1996", "naturaleza": "P"}]}
        out = verificar_ids.avisos_fecha([x], [{"id": "CVE-1999-0128", "publicado": "1999-09-29"}])
        self.assertEqual(len(out), 1)


if __name__ == "__main__":
    unittest.main()
