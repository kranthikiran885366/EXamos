import os
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from revoke_runtime_secrets import revoke_open_directory


class RevocationTests(unittest.TestCase):
    def test_zeroes_open_inode_and_unlinks_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); secret=root/"agent.env"; secret.write_bytes(b"private-token")
            retained=os.open(secret,os.O_RDONLY)
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try:
                self.assertEqual(revoke_open_directory(fd,os.getuid()),1)
                self.assertEqual(os.read(retained,64),bytes(13))
                self.assertFalse(secret.exists())
            finally:
                os.close(fd); os.close(retained)

    def test_rejects_symlinks_and_hardlinks_without_modifying_target(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            target=Path(outside)/"target"; target.write_bytes(b"preserve")
            link=Path(directory)/"link"
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try:
                link.symlink_to(target)
                with self.assertRaises(OSError): revoke_open_directory(fd,os.getuid())
                link.unlink(); os.link(target,link)
                with self.assertRaises(ValueError): revoke_open_directory(fd,os.getuid())
                self.assertEqual(target.read_bytes(),b"preserve")
            finally:
                os.close(fd)

    def test_rejects_nonprivate_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory,0o755); fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try:
                with self.assertRaises(ValueError): revoke_open_directory(fd,os.getuid())
            finally: os.close(fd)


if __name__ == "__main__": unittest.main()
