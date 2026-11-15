"""Pins a new sing-box / Xray release in resources/engines.toml (engines-watch.yml).

Usage: pin-engines.py <engines.toml> <dir with sing-box.zip / xray.zip>; the new versions come from the
environment (SB, XR; empty = unchanged). For each engine: the version, URL and source move to the new
release, the archive pin becomes the SHA-256 of the verified download, and every member is re-pinned from
the bytes inside that archive (its path follows the new version). The file is otherwise left as it is.
"""
import hashlib
import os
import pathlib
import re
import sys
import zipfile

MEMBER = re.compile(r'\{ path = "([^"]+)", install = "([^"]+)", sha256 = "[0-9a-f]{64}" \}')


def bump(text: str, engine: str, new: str, archive: pathlib.Path) -> str:
    start = text.index(f'id = "{engine}"')
    end = text.find("[[", start)
    end = len(text) if end < 0 else end
    block = text[start:end]
    old = re.search(r'^version = "([^"]+)"', block, re.M).group(1)
    block = block.replace(old, new)
    data = archive.read_bytes()
    block = re.sub(
        r'^sha256 = "[0-9a-f]{64}"',
        f'sha256 = "{hashlib.sha256(data).hexdigest()}"',
        block,
        count=1,
        flags=re.M,
    )
    with zipfile.ZipFile(archive) as zf:

        def member(m: re.Match) -> str:
            digest = hashlib.sha256(zf.read(m.group(1))).hexdigest()
            return f'{{ path = "{m.group(1)}", install = "{m.group(2)}", sha256 = "{digest}" }}'

        block = MEMBER.sub(member, block)
    print(f"{engine}: {old} -> {new}")
    return text[:start] + block + text[end:]


def main() -> None:
    manifest, folder = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    text = manifest.read_text(encoding="utf-8")
    for engine, env, name in (("sing-box", "SB", "sing-box.zip"), ("xray", "XR", "xray.zip")):
        version = os.environ.get(env, "").strip()
        if version:
            text = bump(text, engine, version, folder / name)
    manifest.write_text(text, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
