"""Core quantum mechanics simulator primitives, states, and operations."""

from .qubit import QubitState
from .gate import Gate, I, X, Y, Z, H, S, T, CNOT, SWAP, CZ, apply
from .measurement import measure, measure_bell
from .channel import Channel
from .noise import (
    depolarizing_channel,
    amplitude_damping_channel,
    dephasing_channel,
    depolarizing_channel_2,
)
from .stabilizer import StabilizerState
from .latency import (
    DEFAULT_C_FIBER_KM_PER_S,
    ZERO_LATENCY,
    ClassicalLink,
    swap_coordination_delay_s,
    total_coordination_delay_s,
)
from .surface_code import (
    Check,
    DecodeResult,
    MWPMDecoder,
    RotatedSurfaceCode,
    SurfaceCodeError,
    VERIFIED_SITES,
    decode,
    decode_mwpm,
    greedy_match,
    layer_of,
    logical_operator_for,
    matching_graph,
    shortest_paths,
    syndrome_graph,
)
from .memory import (
    Entanglement,
    Memory,
    MemoryArray,
    MemoryError,
    MemoryState,
)
from .scheduler import Scheduler, Event, MoveToPastError
from .photonics import (
    BARRETT_KOK_IDEAL_SUCCESS,
    BarrettKok,
    Detector,
    GenerationAttempt,
    PhotonicLink,
    compare_link_models,
    elementary_link_from_specs,
    ideal_success_from_loss,
    multiplexed_success,
    single_photon_attempt_probability,
)
from .physical import (
    fiber_transmissivity,
    fiber_loss_db,
    dark_count_probability,
    t1_decay_probability,
    t2_dephase_probability,
    memory_fidelity_after_dt,
    bell_pair_fidelity_after_dt,
    depolarizing_from_distance,
)
from .ipc_node import (
    IPCNode,
    TopologyRunner,
    MessageType,
    IPCMessage,
)

__all__ = [
    "QubitState",
    "Gate", "I", "X", "Y", "Z", "H", "S", "T", "CNOT", "SWAP", "apply",
    "measure", "measure_bell",
    "Channel",
    "depolarizing_channel", "amplitude_damping_channel",
    "dephasing_channel", "depolarizing_channel_2",
    # Phase 3
    "StabilizerState",
    "DEFAULT_C_FIBER_KM_PER_S", "ZERO_LATENCY", "ClassicalLink",
    "swap_coordination_delay_s", "total_coordination_delay_s",
    "Check", "DecodeResult", "MWPMDecoder", "RotatedSurfaceCode",
    "SurfaceCodeError", "VERIFIED_SITES", "decode", "decode_mwpm",
    "greedy_match", "layer_of", "logical_operator_for", "matching_graph",
    "shortest_paths", "syndrome_graph",
    "Entanglement", "Memory", "MemoryArray", "MemoryError", "MemoryState",
    "Scheduler", "Event", "MoveToPastError",
    "BARRETT_KOK_IDEAL_SUCCESS", "BarrettKok", "Detector",
    "GenerationAttempt", "PhotonicLink", "compare_link_models",
    "elementary_link_from_specs", "ideal_success_from_loss",
    "multiplexed_success", "single_photon_attempt_probability",
    "fiber_transmissivity", "fiber_loss_db",
    "dark_count_probability",
    "t1_decay_probability", "t2_dephase_probability",
    "memory_fidelity_after_dt", "bell_pair_fidelity_after_dt",
    "depolarizing_from_distance",
    "IPCNode", "TopologyRunner", "MessageType", "IPCMessage",
]
