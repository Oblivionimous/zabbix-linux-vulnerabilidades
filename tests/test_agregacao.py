"""Teste de agregacao do coletor com um trivy simulado.

Um executavel falso chamado trivy devolve tests/fixtures/trivy_sample.json.
O teste confere deduplicacao por CVE, filtro de kernel antigo, contagem de
corrigiveis por classe e ordenacao dos rankings.
"""
import importlib.util
import os
import pathlib
import stat
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "trivy_sample.json"
spec = importlib.util.spec_from_file_location("vuln_collect", ROOT / "src" / "vuln-collect.py")
vc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vc)


class Agregacao(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        fake = pathlib.Path(cls.tmp.name) / "trivy"
        fake.write_text(f"#!/bin/sh\ncat '{FIXTURE}'\n")
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        cls._path = os.environ["PATH"]
        os.environ["PATH"] = cls.tmp.name + os.pathsep + cls._path
        cls._old = (vc.RUNNING, vc.RUNNING_NOARCH)
        vc.RUNNING, vc.RUNNING_NOARCH = "5.14.0-687.52.1.el9_8.x86_64", "5.14.0-687.52.1.el9_8"
        cls.r = vc.collect_trivy()

    @classmethod
    def tearDownClass(cls):
        os.environ["PATH"] = cls._path
        vc.RUNNING, vc.RUNNING_NOARCH = cls._old
        cls.tmp.cleanup()

    def test_status(self):
        self.assertEqual(self.r["status"], "ok")

    def test_kernel_antigo_descartado(self):
        # 3 achados do kernel 570 (CVE-2025-1005 x2 e CVE-2025-1006)
        self.assertEqual(self.r["stale_kernel_findings"], 3)

    def test_cves_unicas_deduplicadas(self):
        # 1001 (2 pacotes), 1002, 1003, 1004, 2001, 2002 = 6
        self.assertEqual(self.r["unique_total"], 6)
        self.assertEqual(self.r["unique_cves"]["CRITICAL"], 1)
        self.assertEqual(self.r["unique_cves"]["HIGH"], 3)

    def test_corrigiveis(self):
        f = self.r["fixable"]
        self.assertEqual((f["CRITICAL"], f["HIGH"], f["MEDIUM"], f["LOW"]), (1, 1, 1, 0))

    def test_corrigiveis_por_classe(self):
        self.assertEqual(self.r["fixable_by_class"]["os-pkgs"]["CRITICAL"], 1)
        self.assertEqual(self.r["fixable_by_class"]["os-pkgs"]["HIGH"], 0)
        self.assertEqual(self.r["fixable_by_class"]["lang-pkgs"]["HIGH"], 1)

    def test_achados_por_classe(self):
        # os-pkgs apos filtro 5 (1001 x2, 1002, 1003, 1004) e lang-pkgs 2
        self.assertEqual(self.r["findings_by_class"], {"os-pkgs": 5, "lang-pkgs": 2})

    def test_ranking_de_cves_por_severidade_e_score(self):
        cves = [c["cve"] for c in self.r["top_cves"]]
        self.assertEqual(cves[0], "CVE-2025-1001")
        self.assertEqual(cves[1], "CVE-2025-1004")

    def test_cve_multipacote_lista_os_dois(self):
        c = next(x for x in self.r["top_cves"] if x["cve"] == "CVE-2025-1001")
        self.assertEqual(c["packages"], "openssl,openssl-libs")
        self.assertTrue(c["fixable"])

    def test_ranking_de_pacotes_inclui_campo_unknown(self):
        self.assertTrue(all("unknown" in p for p in self.r["top_packages"]))

    def test_idade_da_cve_corrigivel_mais_antiga(self):
        self.assertGreater(self.r["oldest_fixable_crit_high_days"], 0)


if __name__ == "__main__":
    unittest.main()
