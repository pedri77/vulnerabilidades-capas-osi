"""Tests for tools/validar.py and tools/generar.py (unittest; also runs under pytest)."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "tools"))

import generar  # noqa: E402
import validar  # noqa: E402


def cargar():
    d = RAIZ / "data"
    cat = yaml.safe_load((d / "capas.yaml").read_text(encoding="utf-8"))
    ens = validar.leer_lista_ens((d / "ens_ids.txt").read_text(encoding="utf-8"))
    prot = {p["id"] for p in yaml.safe_load((d / "smc_protocolos.yaml").read_text(encoding="utf-8"))["protocolos"]}
    ver = yaml.safe_load((d / "verificacion_ids.yaml").read_text(encoding="utf-8"))
    return cat, ens, prot, ver


class TestRepoReal(unittest.TestCase):
    def test_repo_valido(self):
        self.assertEqual(validar.validar_repo(), [])

    def test_ocho_secciones_y_clases_por_capa(self):
        cat, *_ = cargar()
        self.assertEqual([c["id"] for c in cat["capas"]], validar.CAPAS_ESPERADAS)
        for capa in cat["capas"]:
            self.assertGreaterEqual(len(capa["clases"]), 2, capa["id"])

    def test_lista_ens_es_la_de_smc(self):
        _, ens, _, _ = cargar()
        self.assertEqual(len(ens), 73)  # Anexo II del RD 311/2022 según SMC
        self.assertIn("ENS-mp.com.1", ens)
        self.assertIn("ENS-op.exp.2", ens)


class TestMutaciones(unittest.TestCase):
    """Each test breaks one field of a copy of the real catalogue and expects a specific error."""

    def setUp(self):
        self.cat, self.ens, self.prot, self.ver = cargar()
        self.c = copy.deepcopy(self.cat)
        self.clase = self.c["capas"][1]["clases"][0]  # L2-ARP-SPOOFING

    def errores(self, verificacion=None):
        return validar.validar_catalogo(self.c, self.ens, self.prot, verificacion)

    def assertError(self, fragmento, verificacion=None):
        errs = self.errores(verificacion)
        self.assertTrue(any(fragmento in x for x in errs), f"esperaba '{fragmento}' en {errs}")

    def test_cwe_mal_formado(self):
        self.clase["cwe"].append("CWE345")
        self.assertError("CWE mal formado")

    def test_attack_mal_formado(self):
        self.clase["attack"].append("T1557.2")
        self.assertError("ATT&CK mal formada")

    def test_ens_inexistente(self):
        self.clase["ens"].append("ENS-mp.com.9")
        self.assertError("medida ENS inexistente")

    def test_nis2_letra_fuera_de_rango(self):
        self.clase["nis2"].append("NIS2-21.2.k")
        self.assertError("NIS2 mal formado")

    def test_protocolo_desconocido(self):
        self.clase["protocolos"].append("NETBIOS")
        self.assertError("protocolo desconocido")

    def test_url_http(self):
        self.clase["descripcion"] += " Ver http://example.org/arp"
        self.assertError("URL no https")

    def test_consulta_no_coincide(self):
        self.clase["consulta"]["nvd"] = "https://nvd.nist.gov/vuln/search?keyword=otra&resultType=records"
        self.assertError("consulta.nvd no corresponde")

    def test_repo_pedri77_fuera_de_lista(self):
        self.clase["controles"].append("Guía en https://github.com/pedri77/repo-privado-x")
        self.assertError("fuera de la lista blanca")

    def test_guion_largo(self):
        self.clase["nombre"] += " — variante"
        self.assertError("guion largo")

    def test_doble_guion(self):
        self.clase["nombre"] += " -- variante"
        self.assertError("'--' como puntuación")

    def test_id_no_verificado(self):
        self.clase["cwe"].append("CWE-99999")
        self.assertError("sin verificar", verificacion=self.ver)

    def test_id_clase_en_capa_equivocada(self):
        self.clase["id"] = "L3-ARP-SPOOFING"
        self.assertError("debe empezar por L2-")

    def test_falta_campo(self):
        del self.clase["deteccion"]
        self.assertError("faltan ['deteccion']")

    # Contraprueba: the guards must not be so broad that they reject legitimate values.
    # If comprobar_url rejected every pedri77 link, or the "--" check looked inside URLs,
    # these legitimate edits would fail and this test would catch the overreach.
    def test_contraprueba_valores_legitimos_pasan(self):
        self.clase["controles"].append("Repaso en https://pedri77.github.io/modelo_OSI/")
        self.clase["controles"].append("Código en https://github.com/pedri77/security-manager-control")
        self.clase["descripcion"] += " Búsqueda: https://example.org/a--b"
        self.assertEqual(self.errores(self.ver), [])


class TestGenerar(unittest.TestCase):
    def test_html_escapa_y_filtra(self):
        cat, fue, ver, smc = generar.cargar()
        cat = copy.deepcopy(cat)
        cat["capas"][0]["clases"][0]["nombre"] = "<script>alert(1)</script>"
        h = generar.html_pagina(cat, fue, ver, smc)
        self.assertNotIn("<script>alert(1)</script>", h)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", h)
        for cid in validar.CAPAS_ESPERADAS:
            self.assertIn(f'data-capa="{cid}"', h)
        self.assertNotIn("cdn", h.lower())
        self.assertNotIn("<script src", h)

    def test_enlaza_paginas_hermanas(self):
        cat, fue, ver, smc = generar.cargar()
        h = generar.html_pagina(cat, fue, ver, smc)
        self.assertIn("https://pedri77.github.io/modelo_OSI/", h)
        self.assertIn("https://pedri77.github.io/Basicos_Proteccion_Capas_OSI/", h)


if __name__ == "__main__":
    unittest.main()
