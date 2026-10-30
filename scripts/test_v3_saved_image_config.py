import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from scripts.v3_saved_image_config import saved_image_config


class SavedImageConfigTest(unittest.TestCase):
    def test_classic_and_containerd_archive_config_is_not_registry_digest(self):
        raw = json.dumps({"os": "linux", "architecture": "amd64"}).encode()
        digest = hashlib.sha256(raw).hexdigest()
        registry_digest = hashlib.sha256(b"different registry manifest").hexdigest()
        self.assertNotEqual(digest, registry_digest)
        for name in [digest + ".json", "blobs/sha256/" + digest]:
            with self.subTest(config_path=name), tempfile.TemporaryDirectory() as root:
                path = Path(root) / "image.tar"
                self.write(path, [
                    ("manifest.json", json.dumps([{"Config": name}]).encode()),
                    (name, raw),
                ])
                self.assertEqual(saved_image_config(path), digest)

    def test_refuses_wrong_or_ambiguous_metadata(self):
        raw = json.dumps({"os": "linux", "architecture": "amd64"}).encode()
        digest = hashlib.sha256(raw).hexdigest()
        name = "blobs/sha256/" + digest
        manifest = ("manifest.json", json.dumps([{"Config": name}]).encode())
        for scenario in ["missing", "multiple", "duplicate-manifest", "duplicate-config", "checksum", "unsafe-path", "platform", "oversize", "symlink"]:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as root:
                path = Path(root) / "image.tar"
                files = [manifest, (name, raw)]
                if scenario == "missing":
                    files.pop()
                elif scenario == "multiple":
                    files[0] = ("manifest.json", json.dumps([{"Config": name}] * 2).encode())
                elif scenario == "duplicate-manifest":
                    files.append(manifest)
                elif scenario == "duplicate-config":
                    files.append((name, raw))
                elif scenario == "checksum":
                    files[-1] = (name, raw + b" ")
                elif scenario == "unsafe-path":
                    files[0] = ("manifest.json", json.dumps([{"Config": "../" + name}]).encode())
                elif scenario == "platform":
                    raw_other = json.dumps({"os": "linux", "architecture": "arm64"}).encode()
                    other = hashlib.sha256(raw_other).hexdigest() + ".json"
                    files = [("manifest.json", json.dumps([{"Config": other}]).encode()), (other, raw_other)]
                elif scenario == "oversize":
                    files[0] = ("manifest.json", b" " * ((1 << 20) + 1))
                self.write(path, files, name if scenario == "symlink" else None)
                with self.assertRaises((ValueError, json.JSONDecodeError)):
                    saved_image_config(path)

    @staticmethod
    def write(path, files, symlink=None):
        with tarfile.open(path, "w:") as archive:
            for name, raw in files:
                entry = tarfile.TarInfo(name)
                if name == symlink:
                    entry.type, entry.linkname = tarfile.SYMTYPE, "unrelated"
                    archive.addfile(entry)
                else:
                    entry.size = len(raw)
                    archive.addfile(entry, io.BytesIO(raw))


if __name__ == "__main__":
    unittest.main()
