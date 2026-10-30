"""Read the config digest of a local Docker-save TEST fixture.

Docker 29/containerd can return the registry manifest digest in image.Id. It
must not be substituted for the image config digest. Product code still checks
the entire archive and its signed provenance; this module only builds fixtures.
No archive entry is extracted to the filesystem.
"""

import hashlib
import json
import re
import tarfile


def saved_image_config(path):
    with tarfile.open(path, "r:") as archive:
        members = archive.getmembers()
        if len(members) > 4096:
            raise ValueError("too many saved-image entries")

        def read_metadata(name):
            matches = [m for m in members if m.name.removeprefix("./") == name]
            if len(matches) != 1:
                raise ValueError("missing or duplicate saved-image metadata")
            member = matches[0]
            if not member.isfile() or not 0 < member.size <= 1 << 20:
                raise ValueError("invalid saved-image metadata")
            return archive.extractfile(member).read()

        manifests = json.loads(read_metadata("manifest.json"))
        if not isinstance(manifests, list) or len(manifests) != 1:
            raise ValueError("one saved image required")
        manifest = manifests[0]
        if not isinstance(manifest, dict):
            raise ValueError("invalid saved-image manifest")
        name = manifest.get("Config", "")
        if not isinstance(name, str):
            raise ValueError("invalid saved-image config path")
        match = re.fullmatch(r"(?:blobs/sha256/([a-f0-9]{64})|([a-f0-9]{64})\.json)", name)
        if not match:
            raise ValueError("invalid saved-image config path")
        digest = match.group(1) or match.group(2)
        raw = read_metadata(name)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("saved-image config checksum mismatch")
        config = json.loads(raw)
        if not isinstance(config, dict) or config.get("os") != "linux" or config.get("architecture") != "amd64":
            raise ValueError("Linux amd64 saved image required")
        return digest
