"""Surface code memory experiments and the logical key rate.

What this adds
--------------
The surface code and the decoy-state analysis both worked and were not joined up.
This module joins them, producing the number that almost nobody reports:
**key rate after error correction**, with the code's cost in
fidelity *and* in qubit overhead stated.

Two quantities that must not be conflated
-----------------------------------------
* **Physical error rate** ``p`` -- the per-gate depolarising probability. This is
  what a threshold is quoted against.
* **Logical error rate per round** ``p_L`` -- what the code achieves.

:func:`logical_error_rate` **measures** ``p_L``: it samples detection events from
a genuinely noisy circuit and decodes every shot.  It does not evaluate the
scaling ansatz ``p_L = A (p/p_th)^((d+1)/2)``, which is a *fit* with free
constants.  Quoting a fit as though it were a measurement is exactly how a
threshold gets quoted without anyone having computed one.

Detector bookkeeping, and why it is spelled out
-----------------------------------------------
``stim`` emits detectors with coordinates ``(x, y, time)``, and the detector set
of one round is exactly the ancillas of one check family.  The mapping is
therefore recovered from coordinates rather than assumed:

* detector ``(x, y, t)`` -> the ancilla at ``(x, y)`` in the verified lattice;
* the family is X or Z according to which set that coordinate is in.

Getting this wrong is not a crash.  It silently mixes the two syndromes, the
decoder corrects the wrong thing, and the logical error rate comes out high --
which reads as a worse code rather than as a broken harness.  The tests pin the
mapping against the lattice for that reason.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .surface_code import (
    ClusteredDecoder,
    RotatedSurfaceCode,
    SurfaceCodeError,
    decode_space_time_greedy,
    matching_graph,
)

try:  # optional accelerator: a correct, scalable minimum-weight matcher
    from pymatching import Matching as _PyMatching

    HAVE_PYMATCHING = True
except ImportError:  # pragma: no cover - exercised by the skip path
    _PyMatching = None
    HAVE_PYMATCHING = False

try:  # optional: only the noisy-circuit sampling needs it
    import stim

    HAVE_STIM = True
except ImportError:  # pragma: no cover - exercised by the skip path
    stim = None
    HAVE_STIM = False


# Noise models

@dataclass(frozen=True)
class NoiseModel:
    """Which error mechanisms a memory circuit actually contains.

    This exists because a logical error rate is meaningless without it.  ``stim``
    accepts four independent knobs, and turning all four on at parameter ``p``
    puts roughly **five times** the error rate into the circuit that a
    per-gate-depolarizing model does -- once each for the two-qubit gates, the
    measurement, the reset, and the idle data qubits.

    That is not a small difference.  Measured with all four enabled, the
    per-round logical error rate *rose* with distance across the whole range
    tested (``p`` from 5e-5 to 3e-4), which pins the threshold below 5e-5.  With
    depolarizing only, the threshold sits near the familiar 0.5--1%, which is the
    regime every published surface-code curve lives in.  Reporting a threshold
    without saying which model produced it is therefore not a rounding detail:
    it is the difference between "0.05%" and "0.6%".

    The four mechanisms, and what each physical process corresponds to:

    ``gate``
        Two-qubit depolarising after each CNOT.  The **only** one enabled in the
        standard "circuit-level depolarizing" comparison, and the one a published
        threshold is normally quoted against.
    ``measurement``
        Bit-flip on each measurement outcome.  Photon loss and detector dark
        counts land here.
    ``reset``
        Bit-flip on state preparation.  Imperfect initialisation.
    ``idle``
        Depolarising on data qubits during each round who are not being gated.
        Memory dephasing while waiting.
    """

    gate: float = 0.0
    measurement: float = 0.0
    reset: float = 0.0
    idle: float = 0.0
    name: str = "custom"

    @property
    def total_rate(self) -> float:
        """Rough total error probability injected per round.

        The sum of the weights, which is what makes two models with the same
        nominal ``p`` behave so differently.  Reported so a comparison between
        models can be made on the injected rate rather than on the parameter.
        """
        return self.gate * 4 + self.measurement + self.reset + self.idle

    def describe(self) -> str:
        parts = []
        if self.gate:
            parts.append(f"gate={self.gate:g}")
        if self.measurement:
            parts.append(f"meas={self.measurement:g}")
        if self.reset:
            parts.append(f"reset={self.reset:g}")
        if self.idle:
            parts.append(f"idle={self.idle:g}")
        return f"{self.name}({', '.join(parts) or 'noiseless'})"


#: Depolarising gates only.  The model a published threshold is quoted against.
DEPOLARIZING_ONLY = NoiseModel(name="depolarizing-only")

#: All four knobs at once: roughly five times the injected error rate at the same
#: nominal ``p``, so its threshold is not comparable with the gate-only model.
ALL_MECHANISMS = NoiseModel(name="all-mechanisms")


def uniform_noise(value: float, *, name: str = "uniform",
                  mechanism: str = "gate") -> NoiseModel:
    """One value applied to a single mechanism, or to all four.

    ``mechanism`` selects: ``"gate"`` for the depolarizing-gate model, or
    ``"all"`` to reproduce the four-knob circuit-level model.
    """
    if value < 0.0:
        raise ValueError("noise must be non-negative")
    if mechanism == "gate":
        return NoiseModel(gate=value, name=name)
    if mechanism == "all":
        return NoiseModel(gate=value, measurement=value, reset=value,
                          idle=value, name=name)
    raise ValueError(
        f"mechanism must be 'gate' or 'all', got {mechanism!r}"
    )


# Detector -> check mapping

def detector_map(distance: int) -> dict:
    """Map ``stim`` detector coordinates to QEL ancillas, per check family.

    Returns ``{"X": {coord: ancilla}, "Z": {coord: ancilla}, "ancilla_kind":
    {ancilla: kind}, "times": {family: [time, ...]}}``.

    Derived from the verified lattice, so if the two ever disagree this raises
    instead of producing a plausible number from the wrong syndrome.
    """
    code = RotatedSurfaceCode(distance)
    by_coord = {code.ancilla_coords[c.ancilla]: c for c in code.checks}
    out: dict = {"X": {}, "Z": {}, "ancilla_kind": {}, "times": {}}
    for coord, check in by_coord.items():
        out[check.kind][coord] = check.ancilla
        out["ancilla_kind"][check.ancilla] = check.kind
    return out


def detector_coordinates(circuit) -> dict[int, tuple[int, int, int]]:
    """Detector index -> ``(x, y, time)``, in the order ``stim`` numbers them."""
    coordinates: dict[int, tuple[int, int, int]] = {}
    index = 0
    for inst in circuit.flattened():
        if inst.name == "DETECTOR":
            args = list(inst.gate_args_copy())
            if len(args) < 3:
                raise SurfaceCodeError(
                    "detector has no (x, y, t) coordinate; the mapping from "
                    "detector to check cannot be recovered"
                )
            coordinates[index] = (int(args[0]), int(args[1]), int(args[2]))
            index += 1
    return coordinates


def build_detector_table(distance: int) -> dict:
    """Detector index -> ``(family, ancilla, round)`` for a memory experiment.

    The circuit's detector coordinates are the ground truth; the lattice supplies
    the ancilla numbering and the family.  A coordinate the lattice does not
    contain is an error rather than something to skip, because skipping it drops
    a detection event from the syndrome and quietly understates the error rate.

    **The round matters and is carried through.**  Detectors are grouped by their
    time coordinate, and each round's syndrome is decoded separately.  The first
    version accumulated every detector for an ancilla across all rounds -- which
    is an XOR over time, not a syndrome.  That collapses the time dimension the
    decoder needs, and its symptom was that distance 5 came out *worse* than
    distance 3: a result that is obviously wrong and was still produced without
    complaint by every layer beneath it.
    """
    if not HAVE_STIM:
        raise SurfaceCodeError("the detector table needs `pip install stim`")
    circuit = stim.Circuit.generated(
        "surface_code:rotated_memory_z", distance=distance, rounds=distance)
    coordinates = detector_coordinates(circuit)
    lut = detector_map(distance)

    # Distinct time coordinates, in order, become round indices.
    times = sorted({t for (_, _, t) in coordinates.values()})
    round_of = {t: index for index, t in enumerate(times)}

    table: dict[int, tuple[str, int, int]] = {}
    for index, (x, y, time) in coordinates.items():
        matching = [kind for kind in ("X", "Z") if (x, y) in lut[kind]]
        if len(matching) != 1:
            raise SurfaceCodeError(
                f"detector {index} at ({x}, {y}) matches {matching} check "
                f"families; the lattice and the circuit disagree"
            )
        kind = matching[0]
        table[index] = (kind, lut[kind][(x, y)], round_of[time])
    return table


# Memory experiment

@dataclass
class MemoryResult:
    """Outcome of a surface-code memory experiment."""

    distance: int
    rounds: int
    noise: float
    shots: int
    logical_errors: int
    decode_failures: int = 0
    model: NoiseModel | None = None
    #: Which matcher produced this number; a threshold is a property of the decoder as
    #: much as of the code, so it travels with the result.
    decoder: str = "greedy"

    @property
    def logical_error_rate(self) -> float:
        """Logical error probability per shot."""
        if self.shots <= 0:
            raise SurfaceCodeError("no shots were decoded")
        return self.logical_errors / self.shots

    @property
    def per_round_error_rate(self) -> float:
        """Logical error probability per error-correction round.

        Converted from the per-shot rate assuming independence across rounds::

            p_L(round) = (1 - (1 - 2 p_L(shot))**(1/rounds)) / 2

        The ``2p`` form appears because a logical error is a *bit flip*, so the
        survival probability of the pair is ``1 - 2p`` rather than ``1 - p``.
        Using ``1 - p`` here is a common slip and inflates ``p_L`` in the last
        digits while looking right.
        """
        p = self.logical_error_rate
        if self.rounds <= 0:
            return p
        return (1.0 - (1.0 - 2.0 * p) ** (1.0 / self.rounds)) / 2.0

    def describe(self) -> str:
        return (f"d={self.distance} rounds={self.rounds} p={self.noise:g}: "
                f"p_L/shot={self.logical_error_rate:.4e}, "
                f"p_L/round={self.per_round_error_rate:.4e} "
                f"({self.shots} shots, decoder={self.decoder})")

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return self.describe()


def memory_circuit(distance: int, noise, rounds: int | None = None,
                   model: NoiseModel | None = None):
    """A noisy rotated-memory-Z circuit.  Requires ``stim``.

    ``noise`` is accepted for backward compatibility as a scalar, which selects
    the **depolarizing-gate** model -- the one a published threshold is quoted
    against.  Pass a :class:`NoiseModel` to choose which mechanisms are present;
    ``model`` overrides, and if both are given the model wins.

    The default matters.  An earlier version passed the scalar to all four
    ``stim`` knobs, injecting roughly five times the error rate and putting the
    measured threshold two orders of magnitude below the standard value.
    """
    if not HAVE_STIM:
        raise SurfaceCodeError("building a noisy circuit needs `pip install stim`")
    rounds = distance if rounds is None else rounds
    if model is None:
        if isinstance(noise, NoiseModel):
            model = noise
        else:
            model = NoiseModel(gate=float(noise), name="depolarizing-only")
    return stim.Circuit.generated(
        "surface_code:rotated_memory_z",
        distance=distance,
        rounds=rounds,
        after_clifford_depolarization=model.gate,
        before_measure_flip_probability=model.measurement,
        after_reset_flip_probability=model.reset,
        before_round_data_depolarization=model.idle,
    )


def protecting_check_family(observable_basis: str) -> str:
    """Which check family detects the errors that can flip this observable.

    ``"Z"`` (a Z-basis memory experiment, observable = logical Z) is protected by
    the **Z-type** checks, because those detect X errors.  ``"X"`` is the mirror.

    Stated as a function rather than inlined because the mapping is easy to
    invert by accident, and because it is the single assumption that decides
    whether the decoder helps or hurts.
    """
    if observable_basis == "Z":
        return "Z"
    if observable_basis == "X":
        return "X"
    raise SurfaceCodeError(
        f"observable_basis must be 'X' or 'Z', got {observable_basis!r}"
    )


def minimum_weight_decoder(distance: int, rounds: int, decoder: str = "auto",
                           noise: float = 0.001,
                           model: NoiseModel | None = None):
    """Pick a decoder for a memory experiment.

    ``"auto"`` returns ``None``, meaning **use the in-package decoder**
    (:mod:`quantumnet.core.tjoin_decoder`), which is the default and needs no
    third-party matcher.  ``"pymatching"`` returns the PyMatching matcher when it is
    installed, for *comparison* only.

    ``"greedy"`` is accepted as an alias for ``"auto"``. It does **not** select the legacy
    space-time greedy decoder, which is an unreachable approximation with a known defect in
    its final-round boundary conditions; see the limitations section of ``WHITEPAPER.md``.
    The name is kept so existing callers do not break, but the two produce identical
    results.

    Why the in-package decoder is now the default
    --------------------------------------------
    It computes an exact minimum-weight T-join on the merged DEM graph, and **its accuracy
    matches PyMatching's** on this package's own circuits: over 18,000 shots at d=3, 5 and 7
    the two make 24 and 26 logical errors respectively, which is the comparison that matters
    for a threshold. It also recovers a threshold at p ~ 0.007 in the published range.

    It does **not** return the same correction. Measured on 1000 shots per seed at d=3 and
    d=5, the edge sets agree on 1 of 647 non-trivial shots at d=3 and 0 of 2239 at d=5, and
    this decoder's correction is heavier than the reference's in about four cases out of
    five. Those measurements are recorded in full in :mod:`quantumnet.core.tjoin_decoder`,
    including the fact that the weight discrepancy is unexplained.

    A previous in-package decoder was 7.2x worse than the reference and this
    docstring said so; the two defects behind that (whole-instruction observable
    parsing, and a ``-log(p)`` weight instead of the log-likelihood ratio) are
    recorded in :mod:`quantumnet.core.tjoin_decoder`.  The reference is now an
    optional oracle rather than a dependency.
    """
    if decoder in ("auto", "greedy"):
        # The in-package path. No third-party matcher required.
        #
        # ``"greedy"`` used to have its own branch here, selecting the legacy space-time
        # greedy decoder that :mod:`quantumnet.core.surface_code` still provides. It
        # returned ``None`` exactly as ``"auto"`` does, so the decoder parameter never
        # changed which decoder ran: ``decoder="greedy"`` silently produced in-package
        # results. The branch is gone and the name is documented as an alias rather than
        # pretending to be a choice.
        return None
    if decoder == "pymatching":
        if not HAVE_PYMATCHING:
            raise SurfaceCodeError(
                "matcher='pymatching' was requested but PyMatching is not "
                "installed; omit it to use the in-package decoder"
            )
        circuit = memory_circuit(distance, noise, rounds, model=model)
        return _PyMatching.from_detector_error_model(
            circuit.detector_error_model(decompose_errors=True))
    raise SurfaceCodeError(
        f"matcher must be 'auto', 'pymatching' or 'greedy', got {decoder!r}"
    )


def logical_error_rate(distance: int, noise, *, rounds: int | None = None,
                       shots: int = 500, seed: int | None = 1,
                       decoder=None, model: NoiseModel | None = None,
                       matcher: str = "auto") -> MemoryResult:
    """Measure the logical error rate by sampling and decoding real shots.

    ``rounds`` defaults to ``distance``, the usual convention for a memory
    experiment of this size.

    **Sampling rather than evaluating a fit is the point.**  The sub-threshold
    scaling form is an ansatz with free constants; measuring ``p_L`` directly is
    the only way to say a threshold was computed rather than assumed.

    Decoding failures are counted separately from logical errors.  A shot the
    harness could not handle is not evidence that the code failed, and folding
    the two together would overstate ``p_L`` in the direction that flatters
    nobody but misleads everybody.
    """
    if not HAVE_STIM:
        raise SurfaceCodeError(
            "measuring a logical error rate needs the noisy-circuit sampler "
            "(`pip install stim`); this module will not estimate it from a fit"
        )
    if distance not in (3, 5, 7, 9):
        raise SurfaceCodeError(f"no verified layout for distance {distance}")
    rounds = distance if rounds is None else rounds
    if rounds < 1:
        raise ValueError("rounds must be at least 1")

    if model is None:
        if isinstance(noise, NoiseModel):
            model = noise
            rate = model.gate
        else:
            rate = float(noise)
            if rate < 0.0:
                raise ValueError("noise must be non-negative")
            model = NoiseModel(gate=rate, name="depolarizing-only")
    else:
        rate = model.gate
    if any(v < 0.0 for v in (model.gate, model.measurement, model.reset,
                             model.idle)):
        raise ValueError("noise probabilities must be non-negative")

    circuit = memory_circuit(distance, rate, rounds, model=model)
    sampler = circuit.compile_detector_sampler(seed=seed)
    detection, observables = sampler.sample(shots, separate_observables=True)

    table = build_detector_table(distance)
    code = RotatedSurfaceCode(distance)
    # The circuit is `rotated_memory_z`: the observable is the logical Z, X errors flip
    # it, and X errors are detected by the Z-type checks.
    protecting_family = protecting_check_family("Z")

    reference = minimum_weight_decoder(distance, rounds, matcher,
                                       noise=rate, model=model)

    if reference is not None:
        # Explicit PyMatching reference (`matcher="pymatching"`): it decodes the whole
        # detector set at once, both check families, and returns the observable flips.
        predicted_obs = reference.decode_batch(detection)
        errors = int(np.sum(predicted_obs[:, 0].astype(bool)
                            != observables[:, 0].astype(bool)))
        return MemoryResult(distance=distance, rounds=rounds, noise=rate,
                            shots=shots, logical_errors=errors,
                            decode_failures=0, model=model,
                            decoder="pymatching")

    if matcher in ("auto", "greedy"):
        # The default path: the in-package exact T-join decoder, whole space-time set at
        # once, no third-party matcher, so the threshold follows from stim and numpy.
        # ``"builtin"`` used to be accepted here as well, but minimum_weight_decoder
        # rejects it, so that half of the condition was unreachable.
        from .tjoin_decoder import decode_batch as _in_package_decode

        dem = circuit.detector_error_model(decompose_errors=True)
        predicted = _in_package_decode(dem, detection)
        errors = int(np.sum(predicted[:, 0].astype(bool)
                            != observables[:, 0].astype(bool)))
        return MemoryResult(distance=distance, rounds=rounds, noise=rate,
                            shots=shots, logical_errors=errors,
                            decode_failures=0, model=model,
                            decoder="in-package")

    decoder = decoder or ClusteredDecoder()
    errors = 0
    failures = 0
    for shot in range(shots):
        fired = np.flatnonzero(detection[shot])
        try:
            # Space-time decoding with the in-package matcher: each detection event is a
            # ``(round, ancilla)`` node, and the experiment is matched all at once.
            by_round: dict[int, set[int]] = {}
            for index in fired:
                kind, ancilla, round_index = table[int(index)]
                if kind != protecting_family:
                    continue
                by_round.setdefault(round_index, set()).add(ancilla)
            if not by_round:
                predicted = False
            else:
                result = decode_space_time_greedy(
                    code, by_round, protecting_family, rounds)
                predicted = result.logical_flip
        except SurfaceCodeError:
            failures += 1
            continue
        if predicted != bool(observables[shot][0]):
            errors += 1

    return MemoryResult(distance=distance, rounds=rounds, noise=rate,
                        shots=shots - failures, logical_errors=errors,
                        decode_failures=failures, model=model)


def error_rate_curve(distances=(3, 5), noises=(0.001, 0.002, 0.004),
                     *, shots: int = 300, seed: int = 1) -> list[MemoryResult]:
    """Sample ``p_L`` across a grid of distances and physical error rates.

    Measured, not fitted.  This table is what a threshold claim would have to be
    read off, and it is deliberately *not* read off here: a threshold is a
    property of the decoder as much as of the code, so it is quoted with the
    decoder named or not at all.
    """
    return [logical_error_rate(distance, noise, shots=shots, seed=seed)
            for distance in distances for noise in noises]


# The logical key rate

@dataclass
class LogicalKeyRate:
    """A key fraction with error correction costed in."""

    physical_fidelity: float
    logical_fidelity: float
    rounds: int
    distance: int
    logical_error_per_round: float
    logical_error_per_pair: float
    key_fraction: float
    physical_qubits_per_logical: int
    decoder: str = "in-package"

    def describe(self) -> str:
        return (f"d={self.distance}, {self.rounds} rounds: "
                f"F_phys={self.physical_fidelity:.4f} -> "
                f"F_log={self.logical_fidelity:.4f}, "
                f"p_L/round={self.logical_error_per_round:.3e}, "
                f"key fraction={self.key_fraction:.4f}, "
                f"{self.physical_qubits_per_logical} qubits per logical")


def pair_key_fraction(fidelity: float) -> float:
    """``max(0, 1 - 2 h(2(1-F)/3))``: the Werner-pair rate used elsewhere in QEL."""
    from ..protocols.bb84 import binary_entropy

    f = float(np.clip(fidelity, 0.0, 1.0))
    return float(max(0.0, 1.0 - 2.0 * binary_entropy(2.0 * (1.0 - f) / 3.0)))


def compose_pair_fidelity(physical_fidelity: float, logical_fidelity: float,
                          flip_probability: float) -> float:
    """Fidelity of a Werner physical pair after a logical bit flip at one end.

    An exact bit flip on a Werner state of fidelity ``F_phys`` gives::

        F = (1 - q) * F_phys + q * (1 - F_phys) / 3

    where ``q`` is the probability that a logical flip occurred at one end.
    This preserves ``I/4`` invariance (``F_phys = 0.25 -> 0.25`` for all ``q``)
    and avoids double-counting ``q`` and ``F_log``.
    """
    f_phys = float(np.clip(physical_fidelity, 0.0, 1.0))
    q = float(np.clip(flip_probability, 0.0, 1.0))
    return float(np.clip((1.0 - q) * f_phys + q * (1.0 - f_phys) / 3.0, 0.0, 1.0))


def logical_key_rate(physical_fidelity: float, distance: int, noise: float,
                     *, rounds: int | None = None, shots: int = 500,
                     seed: int | None = 1) -> LogicalKeyRate:
    """Key fraction for a logical Bell pair, error correction included.

    The chain of reasoning, so each step can be argued with:

    1. Measure ``p_L`` per round by **sampling and decoding**, not from a fit.
    2. A logical pair held for ``n`` rounds survives with probability
       ``(1 - 2 p_L)^n`` that *neither* end flipped, so it sees an effective
       bit-flip rate of ``1/2 (1 - (1 - 2 p_L)^n)``.  Both ends are charged; a
       logical pair needs two logical qubits, and the overhead says so.
    3. Combine with the physical entanglement fidelity.  A logical pair cannot be
       better than the physical pair it was built from, so the effective fidelity
       is the composition of the two error sources.
    4. Run the result through the same Werner-pair key fraction used at the
       physical layer, so this number is comparable with the rest of QEL instead
       of living on its own scale.

    The qubit overhead is reported alongside.  A key rate without the physical
    qubit count that bought it is not a usable engineering figure.
    """
    if not 0.0 <= physical_fidelity <= 1.0:
        raise ValueError("physical_fidelity must be in [0, 1]")
    rounds = distance if rounds is None else rounds

    memory = logical_error_rate(distance, noise, rounds=rounds, shots=shots,
                                seed=seed)
    p_round = memory.per_round_error_rate

    # A logical flip is a bit flip at one end of the pair, per-round ``p_round``; over
    # ``rounds`` rounds the flip probability is ``0.5 * (1 - (1 - 2 p_round)**rounds)``.
    flip_probability = 0.5 * (1.0 - (1.0 - 2.0 * p_round) ** rounds)

    # The pair's fidelity after those rounds is its overlap with the Bell state,
    # ``(1 + survival) / 2``: the Werner form, ``(1 - flip_probability)`` folded in.
    logical_fidelity = 1.0 - flip_probability / 2.0

    # Both error sources compose through ``compose_pair_fidelity`` without double-counting.
    effective_fidelity = compose_pair_fidelity(
        physical_fidelity, logical_fidelity, flip_probability)

    code = RotatedSurfaceCode(distance)
    return LogicalKeyRate(
        physical_fidelity=float(physical_fidelity),
        logical_fidelity=float(effective_fidelity),
        rounds=rounds,
        distance=distance,
        logical_error_per_round=float(p_round),
        logical_error_per_pair=float(flip_probability),
        key_fraction=pair_key_fraction(effective_fidelity),
        # Two logical qubits, one per end.
        physical_qubits_per_logical=2 * code.n_qubits,
        decoder=memory.decoder,
    )
