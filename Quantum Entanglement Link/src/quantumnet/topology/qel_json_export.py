"""Write a topology to QEL's native JSON schema.

Until now the native `qel-json` importer had no counterpart: a topology built in Python
could not be written out, so `topology build` could only *print* one and nothing
downstream could consume it. That broke the round trip the schema exists for -- the
importer's own tests hand-write their fixtures because nothing could produce them.

The document written here is exactly what :class:`QelJsonImporter` reads, and the tests
assert the round trip rather than the field names, so a schema drift shows up as a failed
round trip instead of as a file that looks right::

    {"schema_version": "1.0",
     "generated_at": "...",
     "nodes": [{"id", "x_km", "y_km", "t1_s", "t2_s", "is_repeater"}],
     "links": [{"a", "b", "length_km", "alpha_db_km"}]}

**Why these fields and not all of them.** `QuantumLink` carries per-link hardware
overrides (dark counts, detector efficiency, pulse rate) that the schema does not name.
They are written when present, under their own names, and the importer ignores unknown
keys -- so a round trip is lossy for those overrides, which is stated in the docstring
rather than hidden. The load-bearing fields -- geometry, coherence times, link lengths
and attenuation -- all survive.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .importers.qel_json import VERSION as QEL_JSON_VERSION

#: Optional per-link fields carried through when the topology sets them.
_OPTIONAL_LINK_FIELDS = ("dark_count_hz", "pulse_rate_hz", "detector_eff")


def topology_to_document(topology, *, generated_at: str | None = None) -> dict:
    """Serialise a topology to the QEL JSON document form.

    ``generated_at`` defaults to now in UTC.  It is a parameter so a caller can produce
    byte-identical output for a fixture, which is what makes the round-trip test
    deterministic.
    """
    nodes = []
    for node in _iter_nodes(topology):
        nodes.append({
            "id": node.node_id,
            "x_km": float(node.x_km),
            "y_km": float(node.y_km),
            "t1_s": float(node.t1_s),
            "t2_s": float(node.t2_s),
            "is_repeater": bool(node.is_repeater),
        })

    links = []
    for link in _iter_links(topology):
        entry = {
            "a": link.a,
            "b": link.b,
            "length_km": float(link.length_km),
            "alpha_db_km": float(link.alpha_db_km),
        }
        for field in _OPTIONAL_LINK_FIELDS:
            value = getattr(link, field, None)
            if value is not None:
                entry[field] = value
        links.append(entry)

    return {
        "schema_version": QEL_JSON_VERSION,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "nodes": nodes,
        "links": links,
    }


def write_qel_json(topology, path, *, generated_at: str | None = None) -> Path:
    """Write ``topology`` to ``path`` in the native schema and return the path.

    Written with an explicit ``utf-8`` encoding and ``\\n`` newlines so the file is
    byte-identical across platforms -- repeated appends to a document from PowerShell's
    legacy code page corrupted a file in this repository twice, and a data format should
    not be able to do that.
    """
    document = topology_to_document(topology, generated_at=generated_at)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, indent=2, sort_keys=False)
        handle.write("\n")
    return target


def _iter_nodes(topology):
    nodes = topology.nodes
    return list(nodes.values()) if isinstance(nodes, dict) else list(nodes)


def _iter_links(topology):
    links = topology.links
    if isinstance(links, dict):
        return list(links.values())
    return list(links)


__all__ = ["topology_to_document", "write_qel_json"]
