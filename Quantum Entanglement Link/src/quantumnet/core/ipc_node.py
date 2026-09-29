"""Multi-process Ghost-Net node architecture.

Each quantum-network node executes as an isolated worker process,
communicating with a central coordinator over local IPC queues.
"""

from __future__ import annotations

import multiprocessing as mp
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MessageType(Enum):
    SCHEDULE_EVENT = "schedule_event"
    STATE_SYNC = "state_sync"
    MEASUREMENT = "measurement"
    FIDELITY_REPORT = "fidelity_report"
    SHUTDOWN = "shutdown"


@dataclass
class IPCMessage:
    kind: "MessageType"
    sender: str
    target: str | None = None
    payload: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Node worker process
# ---------------------------------------------------------------------------
def _node_worker(node_id: str,
                 inbox: mp.Queue,
                 outbox: mp.Queue,
                 t1: float,
                 t2: float):
    """Entry point for a child process representing a network node.

    In a full implementation, each node would hold a local stabilizer
    state, a discrete-event scheduler, and protocol state machines.
    Here we provide the scaffolding that a future Ghost-Net topology
    runner would wire up.
    """
    local_time = 0.0
    running = True
    while running:
        try:
            msg = inbox.get(timeout=0.1)
        except Exception:
            continue
        kind = msg.kind
        if kind == MessageType.SHUTDOWN:
            running = False
        elif kind == MessageType.SCHEDULE_EVENT:
            callback_id = msg.payload.get("callback_id")
            event_kind = msg.payload.get("event_kind")
            event_payload = msg.payload.get("payload", {})
            outbox.put(IPCMessage(
                kind=MessageType.MEASUREMENT,
                sender=node_id,
                payload={
                    "callback_id": callback_id,
                    "event_kind": event_kind,
                    "data": event_payload,
                },
            ))
        elif kind == MessageType.STATE_SYNC:
            state_data = msg.payload.get("state")
            outbox.put(IPCMessage(
                kind=MessageType.STATE_SYNC,
                sender=node_id,
                payload={"state": state_data},
            ))


class IPCNode:
    """Handle to a remote node process.

    Usage
    -----
    >>> a = IPCNode("alice", t1=100.0, t2=50.0)
    >>> b = IPCNode("bob", t1=100.0, t2=50.0)
    >>> a.start()
    >>> b.start()
    >>> a.send(MessageType.SCHEDULE_EVENT, payload={...})
    >>> result = a.recv()
    >>> a.stop()
    >>> b.stop()
    """

    def __init__(self, node_id: str,
                 inbox: mp.Queue | None = None,
                 outbox: mp.Queue | None = None,
                 t1: float = 100.0,
                 t2: float = 50.0):
        self.node_id = node_id
        self._inbox = inbox or mp.Queue()
        self._outbox = outbox or mp.Queue()
        self._t1 = t1
        self._t2 = t2
        self._process: mp.Process | None = None

    def start(self):
        if self._process is not None:
            return
        self._process = mp.Process(
            target=_node_worker,
            args=(self.node_id, self._inbox, self._outbox, self._t1, self._t2),
        )
        self._process.start()

    def stop(self):
        if self._process is None:
            return
        self._inbox.put(IPCMessage(kind=MessageType.SHUTDOWN, sender="coordinator"))
        self._process.join(timeout=3.0)
        if self._process.is_alive():
            self._process.kill()
        self._process = None

    def send(self, kind: MessageType,
             target: str | None = None,
             payload: dict | None = None):
        self._inbox.put(IPCMessage(
            kind=kind, sender="coordinator",
            target=target, payload=payload or {},
        ))

    def recv(self, timeout: float = 1.0) -> IPCMessage | None:
        try:
            return self._outbox.get(timeout=timeout)
        except Exception:
            return None

    @property
    def is_alive(self) -> bool:
        return self._process is not None and self._process.is_alive()


# ---------------------------------------------------------------------------
# Topology runner  (coordinates multiple IPC nodes)
# ---------------------------------------------------------------------------
@dataclass
class TopologyNode:
    node_id: str
    t1: float = 100.0
    t2: float = 50.0
    _handle: IPCNode | None = None

    def start(self):
        self._handle = IPCNode(self.node_id, t1=self.t1, t2=self.t2)
        self._handle.start()

    def stop(self):
        if self._handle:
            self._handle.stop()


class TopologyRunner:
    """Manages a collection of IPCNode processes.

    Provides a single coordinator inbox/outbox pair and dispatches
    messages to the appropriate node.
    """

    def __init__(self):
        self._nodes: dict[str, TopologyNode] = {}

    def add_node(self, node_id: str, t1: float = 100.0, t2: float = 50.0):
        self._nodes[node_id] = TopologyNode(node_id, t1=t1, t2=t2)

    def start_all(self):
        for n in self._nodes.values():
            n.start()

    def stop_all(self):
        for n in self._nodes.values():
            n.stop()

    def send(self, node_id: str, kind: MessageType,
             payload: dict | None = None):
        node = self._nodes.get(node_id)
        if node and node._handle:
            node._handle.send(kind, payload=payload)

    def recv_from(self, node_id: str,
                  timeout: float = 1.0) -> IPCMessage | None:
        node = self._nodes.get(node_id)
        if node and node._handle:
            return node._handle.recv(timeout=timeout)
        return None
