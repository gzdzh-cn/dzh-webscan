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


def saved_image_runtime_id(path, containerd=False):
    """Resolve an offline fixture ID without confusing config and manifest IDs.

    The OCI descriptor must authenticate the same platform/config as the
    Docker-save metadata. This is fixture preparation, never registry proof.
    """
    config = saved_image_config(path)
    if not containerd:
        return "sha256:" + config
    with tarfile.open(path, "r:") as archive:
        def read(name):
            member = archive.getmember(name)
            if not member.isfile() or not 0 < member.size <= 1 << 20:
                raise ValueError("invalid OCI fixture metadata")
            return archive.extractfile(member).read()

        index = json.loads(read("index.json"))
        matches = []
        for descriptor in index.get("manifests", []):
            if descriptor.get("platform") != {"architecture": "amd64", "os": "linux"}:
                continue
            digest = descriptor.get("digest", "")
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
                raise ValueError("invalid OCI fixture digest")
            raw = read("blobs/sha256/" + digest[7:])
            if len(raw) != descriptor.get("size") or hashlib.sha256(raw).hexdigest() != digest[7:]:
                raise ValueError("OCI fixture manifest checksum mismatch")
            manifest = json.loads(raw)
            if manifest.get("config", {}).get("digest") != "sha256:" + config:
                raise ValueError("OCI fixture config mismatch")
            matches.append(digest)
        if len(matches) != 1:
            raise ValueError("one Linux amd64 OCI fixture required")
        return matches[0]
