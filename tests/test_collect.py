"""Testes unitarios da logica pura de src/vuln-collect.py.

Uso: python3 -m unittest discover -s tests -v
"""
import importlib.util
import pathlib
import unittest

SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "vuln-collect.py"
spec = importlib.util.spec_from_file_location("vuln_collect", SRC)
vc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vc)


class KernelAntigo(unittest.TestCase):
    def setUp(self):
        self._r, self._n = vc.RUNNING, vc.RUNNING_NOARCH

    def tearDown(self):
        vc.RUNNING, vc.RUNNING_NOARCH = self._r, self._n

    def test_rpm_kernel_em_uso(self):
        vc.RUNNING = "5.14.0-687.52.1.el9_8.x86_64"
        vc.RUNNING_NOARCH = "5.14.0-687.52.1.el9_8"
        self.assertFalse(vc.stale_kernel("kernel-core", "5.14.0-687.52.1.el9_8"))

    def test_rpm_kernel_antigo(self):
        vc.RUNNING = "5.14.0-687.52.1.el9_8.x86_64"
        vc.RUNNING_NOARCH = "5.14.0-687.52.1.el9_8"
        self.assertTrue(vc.stale_kernel("kernel-core", "5.14.0-570.25.1.el9_6"))

    def test_rpm_versao_com_epoch(self):
        vc.RUNNING = "5.14.0-687.52.1.el9_8.x86_64"
        vc.RUNNING_NOARCH = "5.14.0-687.52.1.el9_8"
        self.assertFalse(vc.stale_kernel("kernel", "0:5.14.0-687.52.1.el9_8"))

    def test_ubuntu_kernel_em_uso(self):
        vc.RUNNING = "6.8.0-142-generic"
        self.assertFalse(vc.stale_kernel("linux-image-6.8.0-142-generic", "6.8.0-142.142"))
        self.assertFalse(vc.stale_kernel("linux-tools-6.8.0-142-generic", "6.8.0-142.142"))

    def test_ubuntu_kernel_antigo_inclui_tools(self):
        vc.RUNNING = "6.8.0-142-generic"
        self.assertTrue(vc.stale_kernel("linux-image-6.8.0-139-generic", "6.8.0-139.139"))
        self.assertTrue(vc.stale_kernel("linux-tools-6.8.0-139", "6.8.0-139.139"))
        self.assertTrue(vc.stale_kernel("linux-tools-6.8.0-139-generic", "6.8.0-139.139"))

    def test_proxmox_kernel(self):
        vc.RUNNING = "7.0.14-19-pve"
        self.assertFalse(vc.stale_kernel("proxmox-kernel-7.0.14-19-pve-signed", "7.0.14-19"))
        self.assertTrue(vc.stale_kernel("proxmox-kernel-6.8.12-9-pve-signed", "6.8.12-9"))

    def test_pacote_comum_nunca_e_kernel(self):
        vc.RUNNING = "6.8.0-142-generic"
        for pkg in ("openssl", "libc6", "curl", "linux-libc-dev", "linux-firmware"):
            self.assertFalse(vc.stale_kernel(pkg, "1.0"), pkg)

    def test_metapacote_sem_digito_nao_e_filtrado(self):
        vc.RUNNING = "6.8.0-142-generic"
        self.assertFalse(vc.stale_kernel("linux-image-generic", "6.8.0-142.142"))


class Cvss(unittest.TestCase):
    def test_prefere_nvd(self):
        v = {"CVSS": {"nvd": {"V3Score": 8.1}, "redhat": {"V3Score": 9.0}}}
        self.assertEqual(vc.cvss(v), 8.1)

    def test_usa_maior_quando_nao_ha_fonte_preferida(self):
        v = {"CVSS": {"outra": {"V3Score": 5.0}, "mais": {"V3Score": 7.2}}}
        self.assertEqual(vc.cvss(v), 7.2)

    def test_sem_cvss(self):
        self.assertEqual(vc.cvss({}), 0.0)
        self.assertEqual(vc.cvss({"CVSS": None}), 0.0)


class Diversos(unittest.TestCase):
    def test_sev_dict_completo(self):
        d = vc.sev_dict({"HIGH": 3})
        self.assertEqual(d, {"CRITICAL": 0, "HIGH": 3, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0})

    def test_ordem_de_severidade(self):
        o = vc.SEV_ORDER
        self.assertGreater(o["CRITICAL"], o["HIGH"])
        self.assertGreater(o["HIGH"], o["MEDIUM"])
        self.assertGreater(o["LOW"], o["UNKNOWN"])


if __name__ == "__main__":
    unittest.main()
