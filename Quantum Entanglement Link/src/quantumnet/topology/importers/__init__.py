"""Topology import registry.

Pick an importer by schema id or file extension; everything else in QEL only
ever calls ``parse``.
"""

from __future__ import annotations

from typing import Iterable

from .base import TopologyImporter, TopologyParseException
from .dot import DotImporter
from .ghostnet import GhostNetImporter
from .qel_json import QelJsonImporter, VERSION as QEL_JSON_VERSION
from .sequencer import (
    SequencerImporter,
    export_document as export_sequencer_document,
    import_document as import_sequencer_document,
    write_config as write_sequencer_config,
)

_IMPORTERS: dict[str, type[TopologyImporter]] = {
    "qel-json": QelJsonImporter,
    "qeljs": QelJsonImporter,
    "qel_json": QelJsonImporter,
    "vantablack": GhostNetImporter,
    "ghostnet": GhostNetImporter,
    "ghost": GhostNetImporter,
    "dot": DotImporter,
    "sequencer": SequencerImporter,
    "sequence": SequencerImporter,
}

#: Accepted file extensions. Resolution is a suffix test, so a longer extension must
#: come before any shorter one it ends with (``.sequence.json`` before ``.json``).
_EXTENSIONS: dict[str, str] = {
    ".qel.json": "qel-json",
    ".qeljs": "qel-json",
    # A plain `.json` is QEL JSON, self-describing via `schema_version`, so files from
    # `topology build --out` import without the caller spelling the suffix a set way.
    ".json": "qel-json",
    ".sequence.json": "sequencer",
    ".seq.json": "sequencer",
    ".ggn": "ghostnet",
    ".dot": "dot",
    ".gv": "dot",
}

_SUPPORTED_SCHEMAS: Iterable[str] = tuple(sorted(_IMPORTERS))


def importer_for(path: str, schema_id: str | None = None) -> type[TopologyImporter]:
    """Resolve the right importer for ``path`` and optional ``schema_id``.

    ``schema_id`` wins when given; otherwise the file extension decides.  A
    ``.dot`` file with ``schema_id="qel-json"`` is an explicit override and
    will be rejected here -- the override belongs in the caller.
    """
    if schema_id:
        importer = _IMPORTERS.get(schema_id)
        if importer is None:
            raise TopologyParseException(
                f"unknown schema_id {schema_id!r}; supported: {_SUPPORTED_SCHEMAS}"
            )
        return importer

    suffix = path.lower()
    # Longest suffix first, so `.sequence.json` beats the plain `.json` alias.
    # Otherwise a SeQUeNCe document routes to the wrong importer.
    for ext, schema in sorted(_EXTENSIONS.items(), key=lambda kv: -len(kv[0])):
        if suffix.endswith(ext):
            return _IMPORTERS[schema]
    raise TopologyParseException(
        f"no importer for {path!r}; known schemas: {_SUPPORTED_SCHEMAS}"
    )


def parse(path: str, schema_id: str | None = None) -> dict:
    """Parse ``path`` through the resolved importer.

    Every importer returns the same canonical shape::

        {"nodes": {id: TopologyNode, ...}, "links": [TopologyLink, ...]}

    The caller is responsible for constructing :class:`Topology` from that
    shape, so that routing/schedule/visualise never learn where a topology
    came from.
    """
    importer = importer_for(path, schema_id)
    return importer(path).parse()
