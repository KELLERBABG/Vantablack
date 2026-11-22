"""SeQUeNCe topology interop -- import and export ``RouterNetTopo`` configs.

Why this exists
---------------
QEL's claim is that a reviewer should be able to run the *same* topology in
SeQUeNCe and in QEL, rather than take a comparison table on trust.  This adapter
is what makes that possible without either project depending on the other.

The format
----------
SeQUeNCe network configs are JSON with two ways to describe a link:

* ``qchannels`` / ``cchannels`` -- explicit, unidirectional, point-to-point.
* ``qconnections`` / ``cconnections`` -- higher-level "auto-expand" forms.

Verified traps this adapter handles
-----------------------------------
Read from SeQUeNCe's own source and its cross-validation documentation; each
one silently corrupts a naive importer:

1. **``attenuation`` is per metre, not per kilometre.**  SeQUeNCe's
   ``QuantumChannel`` takes dB/m, so a 0.2 dB/km fibre is written as
   ``0.0002``.  Reading that as dB/km makes every link 1000x too lossy.
2. **A ``qconnection`` halves its declared distance.**  SeQUeNCe synthesises a
   midpoint BSM node and two half-length arms, so the declared distance is the
   *full* link and each arm is ``distance // 2``.  The canonical QEL topology
   records the full link once.
3. **An explicit ``qchannel`` pair is also a split link.**  ``router -> BSM``
   plus ``BSM2 -> router`` are two halves, and the midpoint name may carry a
   ``BSM.`` prefix or a bare ``BSM_`` stem.  Halves must be summed, not
   treated as independent links.
4. **BSM/controller nodes are scaffolding, not sites.**  Importing them as
   nodes inflates the candidate-site list for the placement optimiser.
5. **Classical channels are mandatory companions.**  ``_add_qconnections``
   asserts if a ``qconnection`` has no matching classical channel between its
   router pair, so an exporter that omits ``cconnections`` emits a config that
   crashes SeQUeNCe.
6. **Time is integer picoseconds**; distances are km; delays are ps.

Round-trip guarantee
--------------------
``import(export(t))`` and ``export(import(c))`` preserve link endpoints and
lengths.  Both directions are covered by tests; the distance-doubling and
half-link rules are why that is non-trivial.
"""

from __future__ import annotations

import json
from math import isfinite
from pathlib import Path

from .base import (
    TopologyImporter,
    TopologyLink,
    TopologyNode,
    TopologyParseException,
)

#: Node types that are simulation scaffolding rather than network sites.
_SCAFFOLDING_TYPES = frozenset({
    "BSMNode", "BSM", "Controller", "Barretter", "QuantumSwitch",
})

#: Speed of light in fibre, for a classical delay when absent: 2.0e8 m/s, the community
#: standard (QuISP: ``distance / 200000km * 1s``); SeQUeNCe spans 2.0-2.05e8.
C_FIBER_KM_PER_S = 200_000.0

#: Default fibre attenuation in dB/km when a config omits it (1550 nm).
DEFAULT_ALPHA_DB_KM = 0.2


def _finite_float(value, what: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise TopologyParseException(
            f"{what}: expected a number, got {value!r}"
        ) from exc
    if not isfinite(number):
        raise TopologyParseException(f"{what}: must be finite, got {value!r}")
    return number


def _is_scaffolding(node_type: str, name: str) -> bool:
    """True for nodes that are simulation machinery, not network sites."""
    if node_type in _SCAFFOLDING_TYPES:
        return True
    stem = name.split(".", 1)[0]
    return stem.startswith("BSM") or stem in _SCAFFOLDING_TYPES


def _attenuation_to_db_km(value, what: str) -> float:
    """SeQUeNCe stores attenuation in dB/m; QEL works in dB/km."""
    atten_db_m = _finite_float(value, what)
    if atten_db_m <= 0.0:
        return DEFAULT_ALPHA_DB_KM
    return atten_db_m * 1000.0


class SequencerImporter(TopologyImporter):
    """Read a SeQUeNCe ``RouterNetTopo`` config into a canonical topology.

    ``parse`` reads a path; :meth:`parse_document` takes an in-memory dict.
    SeQUeNCe's own ``Topology._load`` accepts both, so a counterpart exporter
    can hand over a dict and skip the file round-trip.
    """

    def parse(self) -> dict:
        try:
            text = Path(self.path).read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise TopologyParseException(f"{self.path}: no such file") from exc
        except OSError as exc:
            raise TopologyParseException(f"{self.path}: {exc}") from exc
        try:
            data = json.loads(text, parse_constant=self._reject_constant)
        except json.JSONDecodeError as exc:
            raise TopologyParseException(
                f"{self.path}: invalid JSON at line {exc.lineno}: {exc.msg}"
            ) from exc
        return self.parse_document(data)

    @staticmethod
    def _reject_constant(value: str) -> None:
        raise TopologyParseException(
            f"non-finite constant {value!r} in SeQUeNCe config JSON"
        )

    # parse

    def parse_document(self, data: dict) -> dict:
        if not isinstance(data, dict):
            raise TopologyParseException(
                f"{self.path}: top level must be an object"
            )

        raw_nodes = data.get("nodes")
        if not isinstance(raw_nodes, list):
            raise TopologyParseException(f"{self.path}: 'nodes' must be an array")

        out_nodes: dict[str, TopologyNode] = {}
        scaffolding: set[str] = set()
        for index, node in enumerate(raw_nodes):
            if not isinstance(node, dict):
                raise TopologyParseException(
                    f"{self.path}: nodes[{index}] must be an object"
                )
            name = node.get("name")
            if not isinstance(name, str) or not name:
                raise TopologyParseException(
                    f"{self.path}: nodes[{index}].name must be a non-empty string"
                )
            node_type = str(node.get("type", "QuantumRouter"))
            if _is_scaffolding(node_type, name):
                scaffolding.add(name)
                continue
            if name in out_nodes:
                raise TopologyParseException(
                    f"{self.path}: duplicate node name {name!r}"
                )
            out_nodes[name] = TopologyNode(
                id=name,
                x_km=_finite_float(node.get("x_km", 0.0),
                                   f"{self.path}: nodes[{index}].x_km"),
                y_km=_finite_float(node.get("y_km", 0.0),
                                   f"{self.path}: nodes[{index}].y_km"),
                t1_s=_finite_float(node.get("t1_s", 100.0),
                                   f"{self.path}: nodes[{index}].t1_s"),
                t2_s=_finite_float(node.get("t2_s", 50.0),
                                   f"{self.path}: nodes[{index}].t2_s"),
                is_repeater=bool(node.get(
                    "is_repeater",
                    node_type in ("QuantumRouter", "Repeater")
                    and name.lower().startswith("r"),
                )),
            )

        halves: list[TopologyLink] = []
        whole: list[TopologyLink] = []

        for index, chan in enumerate(data.get("qchannels") or []):
            if not isinstance(chan, dict):
                raise TopologyParseException(
                    f"{self.path}: qchannels[{index}] must be an object"
                )
            src, dst = chan.get("source"), chan.get("destination")
            if not isinstance(src, str) or not isinstance(dst, str):
                raise TopologyParseException(
                    f"{self.path}: qchannels[{index}] needs 'source' and "
                    f"'destination'"
                )
            link = TopologyLink(
                a=src, b=dst,
                length_km=_finite_float(
                    chan.get("distance"),
                    f"{self.path}: qchannels[{index}].distance"),
                alpha_db_km=_attenuation_to_db_km(
                    chan.get("attenuation", 0.0002),
                    f"{self.path}: qchannels[{index}].attenuation"),
            )
            (halves if (src in scaffolding or dst in scaffolding)
             else whole).append(link)

        for index, conn in enumerate(data.get("qconnections") or []):
            if not isinstance(conn, dict):
                raise TopologyParseException(
                    f"{self.path}: qconnections[{index}] must be an object"
                )
            a, b = conn.get("node1"), conn.get("node2")
            if not isinstance(a, str) or not isinstance(b, str):
                raise TopologyParseException(
                    f"{self.path}: qconnections[{index}] needs 'node1' and "
                    f"'node2'"
                )
            if a in scaffolding or b in scaffolding:
                raise TopologyParseException(
                    f"{self.path}: qconnections[{index}] connects scaffolding "
                    f"node ({a!r}/{b!r}); use qchannels for explicit arms"
                )
            # A qconnection's declared distance is the FULL link (trap #2).
            whole.append(TopologyLink(
                a=a, b=b,
                length_km=_finite_float(
                    conn.get("distance"),
                    f"{self.path}: qconnections[{index}].distance"),
                alpha_db_km=_attenuation_to_db_km(
                    conn.get("attenuation", 0.0002),
                    f"{self.path}: qconnections[{index}].attenuation"),
            ))

        out_links = whole + self._collapse_halves(halves, out_nodes)

        if not out_nodes:
            raise TopologyParseException(
                f"{self.path}: no network nodes found (scaffolding only?)"
            )
        return {"nodes": out_nodes, "links": out_links}

    @staticmethod
    def _collapse_halves(halves: list[TopologyLink],
                         out_nodes: dict[str, TopologyNode]) -> list[TopologyLink]:
        """Merge ``router -> BSM`` half-links into whole links.

        An explicit ``qchannel`` that terminates on a scaffolding node is half
        of a physical link.  Two halves sharing the midpoint add up.  An
        unpaired half is dropped: half a link carries no end-to-end
        entanglement, and inventing an endpoint for it would be a fabrication.
        """
        by_midpoint: dict[str, list[TopologyLink]] = {}
        for link in halves:
            endpoints = (link.a, link.b)
            mid = next((e for e in endpoints if e not in out_nodes), None)
            if mid is None:
                # Both ends are real nodes after all; it is a whole link.
                by_midpoint.setdefault("\0whole", []).append(link)
                continue
            by_midpoint.setdefault(mid, []).append(link)

        merged: list[TopologyLink] = list(by_midpoint.pop("\0whole", []))
        for mid, group in by_midpoint.items():
            if len(group) == 1:
                continue  # unpaired half: not a link
            lengths = [g.length_km for g in group]
            endpoints = []
            for g in group:
                endpoints.append(g.b if g.a == mid else g.a)
            # A router->BSM->router pair sums the two arm lengths.
            for i in range(len(endpoints) - 1):
                a, b = endpoints[i], endpoints[i + 1]
                if a == b:
                    continue
                merged.append(TopologyLink(
                    a=a, b=b,
                    length_km=sum(lengths),
                    alpha_db_km=min(g.alpha_db_km for g in group),
                ))
        return merged


# Export

def export_document(topology, topology_name: str = "qel_export",
                    stop_time_ps: int = 1_000_000_000_000,
                    memory_size: int = 50, seed: int = 0) -> dict:
    """Render a canonical topology as a SeQUeNCe ``RouterNetTopo`` config.

    Emits ``qconnections`` (auto-expand) plus the ``cconnections`` they
    require -- trap #5: SeQUeNCe asserts if a ``qconnection`` has no matching
    classical channel, so the classical companion is not optional.

    Because a ``qconnection`` is halved on load (trap #2), the distance written
    here is the full link length and SeQUeNCe will build two arms of half that.

    ``topology`` may be a canonical dict (``{"nodes", "links"}``) or a
    :class:`~quantumnet.topology.graph.QuantumTopology`.
    """
    nodes, links = _coerce_topology(topology)
    node_names = sorted(nodes)

    out_nodes = []
    for name in node_names:
        out_nodes.append({
            "name": name,
            "type": "QuantumRouter",
            "seed": seed,
            "memo_size": memory_size,
        })

    out_qconnections, out_cconnections = [], []
    for a, b, length_km, alpha_db_km in links:
        if a not in nodes or b not in nodes:
            raise TopologyParseException(
                f"link {a}-{b} references a node not in the topology"
            )
        out_qconnections.append({
            "node1": a,
            "node2": b,
            # dB/km -> dB/m.  Trap #1.
            "attenuation": alpha_db_km / 1000.0,
            "distance": length_km,
            "type": "meet_in_the_middle",
        })
        # Mandatory classical companion (trap #5), delay from the fibre.
        delay_ps = int(length_km / C_FIBER_KM_PER_S * 1e12)
        out_cconnections.append({"node1": a, "node2": b, "delay": delay_ps})

    # Every router pair needs a classical path for the auto-expanded BSM nodes too;
    # SeQUeNCe averages the declared delays for those.
    for i, a in enumerate(node_names):
        for b in node_names[i + 1:]:
            if not any(c["node1"] == a and c["node2"] == b
                       for c in out_cconnections):
                out_cconnections.append({
                    "node1": a, "node2": b,
                    "delay": int(1_000_000),  # 1 us default for non-adjacent
                })

    return {
        "nodes": out_nodes,
        "qconnections": out_qconnections,
        "cconnections": out_cconnections,
        "stop_time": int(stop_time_ps),
    }


def write_config(topology, path: str | Path, **kwargs) -> Path:
    """Write a SeQUeNCe config to ``path``.  Returns the path written."""
    document = export_document(topology, **kwargs)
    out = Path(path)
    out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return out


def import_document(data: dict) -> dict:
    """Import an in-memory SeQUeNCe config dict (no file needed)."""
    return SequencerImporter("<dict>").parse_document(data)


def _coerce_topology(topology):
    """Return ``(nodes, links)`` as ``(dict[str, node], list[(a,b,len,alpha)])``."""
    if isinstance(topology, dict):
        nodes = topology.get("nodes", {})
        raw_links = topology.get("links", [])
    else:
        nodes = getattr(topology, "nodes", {})
        raw_links = list(getattr(topology, "links", {}).values())

    links = []
    for link in raw_links:
        if isinstance(link, dict):
            links.append((link["a"], link["b"], float(link["length_km"]),
                          float(link.get("alpha_db_km", DEFAULT_ALPHA_DB_KM))))
        else:
            links.append((link.a, link.b, float(link.length_km),
                          float(getattr(link, "alpha_db_km", DEFAULT_ALPHA_DB_KM))))
    return nodes, links
