from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class StageProfileTests(unittest.TestCase):
    def test_stages_executable_controls_without_deployment_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            subprocess.run(["bash", str(ROOT / "scripts/stage-security-profile.sh"), directory],
                           check=True, capture_output=True, text=True)
            for path in ("usr/local/bin/sppio-securityd",
                         "usr/lib/examos/bpf/examos_lsm.bpf.o",
                         "usr/lib/examos/bpf/examos_xdp_filter.bpf.o",
                         "etc/ima/ima-policy",
                         "usr/local/libexec/examos/keylime_gate.py",
                         "usr/local/libexec/examos/revoke_runtime_secrets.py"):
                self.assertTrue((stage / path).is_file(), path)
            for name in ("sppio-securityd", "examos-bpf-lsm", "examos-xdp-filter", "examos-pfr-verify", "examos-ab-commit"):
                link = stage / f"etc/systemd/system/multi-user.target.wants/{name}.service"
                self.assertTrue(link.is_symlink() and link.resolve().is_file(), name)
            self.assertFalse((stage / "etc/examos/keylime-gate.json").exists())
            self.assertEqual((stage / "etc/examos/security-profile").read_text(), "measured\n")


if __name__ == "__main__": unittest.main()
