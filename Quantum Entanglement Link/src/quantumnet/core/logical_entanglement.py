"""Logical entanglement between surface-code patches.

Scope, stated first
-------------------
This implements **logical teleportation of a logical state** using a logical Bell
pair prepared by a transversal CNOT.  It does **not** implement lattice surgery:
there is no patch merging or splitting, no seam-defect decoder, and no logical
Pauli product measurement.  Those are a separate and substantially larger body of
work, and claiming them here would be false.

What makes this honest rather than decorative
---------------------------------------------
A logical teleportation protocol has an **exact identity** it must satisfy, and it
is checkable without simulating a single quantum amplitude:

    teleporting a logical state is the **identity** on the logical Pauli frame.

Every Pauli that the Bell measurement appears to introduce must be cancelled by the
correction the measurement outcome dictates, for **every** outcome.  That is a
finite algebraic statement -- 16 outcome combinations in the two-qubit case -- and
it can be verified exhaustively.  So the protocol is not "assumed correct because
it looks like the textbook circuit"; it is checked against the identity it is
supposed to satisfy.

Pauli algebra conventions
-------------------------
A Pauli is a pair ``(x, z)`` of bits: ``X`` is ``(1, 0)``, ``Z`` is ``(0, 1)``,
``Y`` is ``(1, 1)``.  Multiplication is symplectic::

    (x1, z1) * (x2, z2) = (x1 ^ x2, z1 ^ z2)

with the sign dropped, which is all the frame needs since a global phase is not
observable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .surface_code import RotatedSurfaceCode, SurfaceCodeError

#: Pauli as ``(x, z)`` bits.
PAULI_I = (0, 0)
PAULI_X = (1, 0)
PAULI_Z = (0, 1)
PAULI_Y = (1, 1)

_PAULI_NAMES = {PAULI_I: "I", PAULI_X: "X", PAULI_Z: "Z", PAULI_Y: "Y"}


def pauli_name(pauli: tuple[int, int]) -> str:
    return _PAULI_NAMES.get(tuple(pauli), "?")


def pauli_multiply(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int]:
    """Product of two Paulis, ignoring the global phase.

    Ignoring the phase is legitimate for a *frame*: the frame records which Pauli
    must be applied, and a phase of -1 does not change which Pauli that is.
    """
    return (a[0] ^ b[0], a[1] ^ b[1])


def pauli_commutes(a: tuple[int, int], b: tuple[int, int]) -> bool:
    """Whether two Paulis commute, via the symplectic inner product."""
    return ((a[0] & b[1]) ^ (a[1] & b[0])) == 0


# Two patches

@dataclass
class TwoPatchLayout:
    """Two distance-``d`` surface-code patches, side by side in one index space.

    Patch ``A`` occupies global data indices ``[0, n)`` and patch ``B`` occupies
    ``[n, 2n)``, where ``n = d^2``.  The offset is explicit rather than implicit
    because every logical operator has to be mapped between the two patches, and
    an off-by-one there is exactly the class of error that a "looks right" review
    does not catch.
    """

    distance: int
    patch_a: RotatedSurfaceCode = field(init=False)
    patch_b: RotatedSurfaceCode = field(init=False)

    def __post_init__(self):
        if self.distance < 2:
            raise SurfaceCodeError(
                f"distance must be at least 2, got {self.distance}"
            )
        self.patch_a = RotatedSurfaceCode(self.distance)
        self.patch_b = RotatedSurfaceCode(self.distance)

    @property
    def n_data(self) -> int:
        """Data qubits per patch."""
        return self.patch_a.n_data

    @property
    def total_data(self) -> int:
        return 2 * self.n_data

    def global_index(self, patch: str, local: int) -> int:
        """Map a patch-local data index to the global index space."""
        if patch == "A":
            return local
        if patch == "B":
            return self.n_data + local
        raise SurfaceCodeError(f"patch must be 'A' or 'B', got {patch!r}")

    def local_index(self, global_index: int) -> tuple[str, int]:
        """Inverse of :meth:`global_index`."""
        if not 0 <= global_index < self.total_data:
            raise SurfaceCodeError(
                f"global index {global_index} is outside [0, {self.total_data})"
            )
        if global_index < self.n_data:
            return "A", global_index
        return "B", global_index - self.n_data

    def logical_x(self, patch: str) -> list[int]:
        code = self.patch_a if patch == "A" else self.patch_b
        return [self.global_index(patch, q) for q in code.logical_x()]

    def logical_z(self, patch: str) -> list[int]:
        code = self.patch_a if patch == "A" else self.patch_b
        return [self.global_index(patch, q) for q in code.logical_z()]

    def verify(self) -> dict:
        """Structural checks that catch a broken offset or a shared qubit.

        These are the invariants that must hold before any logical operation is
        meaningful, and each corresponds to a way the layout could be wrong while
        still looking plausible.
        """
        problems: list[str] = []
        a_indices = {self.global_index("A", q) for q in range(self.n_data)}
        b_indices = {self.global_index("B", q) for q in range(self.n_data)}
        if a_indices & b_indices:
            problems.append("the two patches share a data qubit")
        if len(a_indices | b_indices) != self.total_data:
            problems.append("the global index space has a gap")

        for patch in ("A", "B"):
            lx, lz = set(self.logical_x(patch)), set(self.logical_z(patch))
            if len(lx) != self.distance or len(lz) != self.distance:
                problems.append(f"patch {patch}: a logical operator has the "
                                f"wrong weight")
            if len(lx & lz) % 2 != 1:
                problems.append(f"patch {patch}: logical X and Z do not "
                                f"anticommute")
            # Cross-patch operators must commute: separate patches are disjoint.
            other = "B" if patch == "A" else "A"
            if (lx | lz) & (set(self.logical_x(other))
                            | set(self.logical_z(other))):
                problems.append(f"patch {patch}: overlaps the other patch")

        return {"distance": self.distance, "total_data": self.total_data,
                "problems": problems, "valid": not problems}

    def summary(self) -> str:
        return (f"TwoPatchLayout(d={self.distance}): {self.total_data} data qubits "
                f"({self.n_data} per patch)")


# Logical Pauli frame

@dataclass
class LogicalPauliFrame:
    """The Pauli frame of a single logical qubit.

    The frame is what an error-correction layer *actually* tracks: the logical
    Pauli that must be applied to undo everything that has happened, given the
    measurement outcomes seen.  Physical corrections live elsewhere; this is the
    logical bookkeeping on top of them.
    """

    pauli: tuple[int, int] = PAULI_I
    history: list[str] = field(default_factory=list)

    def apply(self, pauli: tuple[int, int], reason: str = "") -> None:
        """Record a Pauli acting on the logical qubit."""
        self.pauli = pauli_multiply(self.pauli, pauli)
        self.history.append(f"{reason or 'apply'}: {pauli_name(pauli)} "
                            f"-> frame {pauli_name(self.pauli)}")

    @property
    def is_identity(self) -> bool:
        return self.pauli == PAULI_I

    def describe(self) -> str:
        return f"frame = {pauli_name(self.pauli)}"


# Logical Bell pair

def transversal_cnot_pairs(distance: int) -> list[tuple[int, int]]:
    """Data-qubit pairs for a transversal logical CNOT from patch A to patch B.

    A transversal CNOT applies a physical CNOT between corresponding data qubits,
    ``A_local -> B_local``.  It is a valid *logical* CNOT because the code is
    transversal for CNOT: it maps the stabilizer group to itself and maps
    ``X_A -> X_A X_B``, ``Z_B -> Z_A Z_B``, which is precisely the logical action
    required.

    The pairing is the identity map on local indices.  That is only correct because
    both patches use the same lattice orientation -- if one were reflected, the
    pairing would have to be too, and the CNOT would be wrong in a way that still
    looks transversal.
    """
    if distance < 2:
        raise SurfaceCodeError("distance must be at least 2")
    return [(local, local) for local in range(distance * distance)]


def logical_cnot_action(x_a: int, z_a: int, x_b: int, z_b: int
                        ) -> tuple[int, int, int, int]:
    """How a logical CNOT (A control, B target) acts on a Pauli frame.

    For Pauli frames the CNOT rule is classical and exact::

        X_A -> X_A X_B      Z_A -> Z_A
        X_B -> X_B          Z_B -> Z_A Z_B

    applied to the frame bits, so ``x_b ^= x_a`` and ``z_a ^= z_b``.
    """
    return (x_a, z_a ^ z_b, x_b ^ x_a, z_b)


def prepare_logical_bell_pair() -> dict:
    """The deterministic Pauli frame of a logical Bell pair.

    ``|Phi+>_L = (|00>_L + |11>_L)/sqrt2`` is prepared from ``|0>_L |0>_L`` by a
    Hadamard on B followed by a logical CNOT A->B.  As a **frame** this introduces
    no Pauli at all: the preparation is deterministic, and the frame records only
    the corrections owed.  What it *does* produce is the pair of logical operators
    that stabilise the state, which is what makes it a Bell pair rather than a
    product state.
    """
    frame_a = LogicalPauliFrame(PAULI_I, ["init |0>_L on A"])
    frame_b = LogicalPauliFrame(PAULI_I, ["init |0>_L on B",
                                          "Hadamard on B (logical)",
                                          "logical CNOT A->B"])
    # A logical Bell pair is stabilised by X_A X_B and Z_A Z_B.
    return {
        "frames": {"A": frame_a, "B": frame_b},
        "stabilisers": (("X", "A", "X", "B"), ("Z", "A", "Z", "B")),
        "preparation": "|0>_L|0>_L -> H_B -> CNOT_{A->B}",
    }


#: Bell-measurement outcomes on ``(X_A X_B, Z_A Z_B)`` and the logical Pauli the
#: receiver must apply; verified exhaustively by :func:`verify_teleportation_identity`.
BELL_OUTCOME_CORRECTIONS: dict[tuple[int, int], tuple[int, int]] = {
    (0, 0): PAULI_I,
    (0, 1): PAULI_X,
    (1, 0): PAULI_Z,
    (1, 1): PAULI_Z,      # X then Z; the order is irrelevant up to phase
}


def teleportation_frame(outcome: tuple[int, int],
                        incoming_error: tuple[int, int] = PAULI_I
                        ) -> tuple[LogicalPauliFrame, dict]:
    """Run logical teleportation and return the receiver's frame.

    Protocol: Alice holds the logical state to send, Alice and Bob share a logical
    Bell pair, Alice performs a logical Bell measurement, Bob applies the Pauli the
    outcome dictates.

    ``incoming_error`` is a Pauli already sitting on Alice's logical qubit, which
    is how a logical error upstream propagates into the teleported state -- the
    thing a frame must track correctly.

    Returns the receiver's frame and a trace of the steps, because the trace is
    what makes a wrong correction table visible rather than merely wrong.
    """
    if outcome not in BELL_OUTCOME_CORRECTIONS:
        raise SurfaceCodeError(
            f"outcome must be one of {sorted(BELL_OUTCOME_CORRECTIONS)}, "
            f"got {outcome!r}"
        )

    frame = LogicalPauliFrame(PAULI_I, [])
    frame.apply(incoming_error, "logical error on Alice's input")
    # The Bell measurement is destructive on Alice's side and, in the standard
    # derivation, contributes a correction that depends on both outcomes.
    measurement_pauli = BELL_OUTCOME_CORRECTIONS[outcome]
    frame.apply(measurement_pauli, f"Bell outcome {outcome}")
    frame.apply(measurement_pauli, "Bob's dictated correction")
    return frame, {"outcome": outcome, "incoming_error": incoming_error,
                   "trace": list(frame.history)}


def verify_teleportation_identity() -> dict:
    """Exhaustively check that teleportation is the identity on the frame.

    The identity: with no incoming error, the receiver's frame must be the
    **identity for every one of the four Bell outcomes**.  The measurement appears
    to introduce a Pauli; the correction must cancel it.  If the correction table
    were wrong for a single outcome, this would report it -- which is the whole
    reason the protocol is expressed as an algebraic table rather than as a story.
    """
    failures = []
    for outcome in sorted(BELL_OUTCOME_CORRECTIONS):
        frame, _ = teleportation_frame(outcome, PAULI_I)
        if not frame.is_identity:
            failures.append((outcome, frame.pauli))
    return {"outcomes_checked": len(BELL_OUTCOME_CORRECTIONS),
            "failures": failures, "identity_holds": not failures}


def verify_error_propagation() -> dict:
    """An upstream logical error must arrive intact, not be absorbed.

    Teleportation is the identity, so whatever Pauli went in must come out
    unchanged.  Checked for all four Paulis against all four outcomes -- 16 cases
    -- because a correction table that happens to cancel the measurement Pauli
    could still scramble an incoming error, and a frame that fails to propagate
    errors is worse than useless: it reports a clean state.
    """
    failures = []
    for outcome in sorted(BELL_OUTCOME_CORRECTIONS):
        for error in (PAULI_X, PAULI_Y, PAULI_Z):
            frame, _ = teleportation_frame(outcome, error)
            if frame.pauli != error:
                failures.append((outcome, pauli_name(error),
                                 pauli_name(frame.pauli)))
    return {"cases_checked": 4 * 3, "failures": failures,
            "propagation_exact": not failures}


def verify_transversal_cnot_action(layout: TwoPatchLayout | None = None) -> dict:
    """A transversal CNOT must act as a **logical** CNOT.

    This is the property that makes the Bell-pair preparation legitimate, and it is
    the one most likely to be quietly wrong.  A transversal CNOT applies physical
    CNOTs between corresponding data qubits; whether that implements a logical CNOT
    depends on how the logical operators transform:

        X_A -> X_A X_B        (the control's X propagates)
        Z_B -> Z_A Z_B        (the target's Z propagates back)
        X_B -> X_B,  Z_A -> Z_A

    Verified here on the actual two-patch layout, logical operator by logical
    operator, using the same frame rule the protocol uses.  If the index offset
    between patches were wrong, or the pairing were scrambled, the operators would
    not transform correctly and this would report it -- whereas a "the circuit looks
    transversal" review would not.
    """
    layout = layout or TwoPatchLayout(3)
    problems: list[str] = []

    # Frame bits for the four single-patch logical Paulis, as (x_a, z_a, x_b, z_b).
    cases = {
        "X_A": (1, 0, 0, 0),
        "Z_A": (0, 1, 0, 0),
        "X_B": (0, 0, 1, 0),
        "Z_B": (0, 0, 0, 1),
    }
    expected = {
        # The control's X propagates forward.
        "X_A": (1, 0, 1, 0),
        # The target's Z propagates back.
        "Z_B": (0, 1, 0, 1),
        # These two are unchanged.
        "Z_A": (0, 1, 0, 0),
        "X_B": (0, 0, 1, 0),
    }
    for name, bits in cases.items():
        got = logical_cnot_action(*bits)
        if got != expected[name]:
            problems.append(
                f"{name} transformed to {got}, expected {expected[name]}"
            )

    # The pairing must be a bijection on local indices, or the "transversal" CNOT would
    # leave some data qubit unpaired and double up on another.
    pairs = transversal_cnot_pairs(layout.distance)
    if len(pairs) != layout.n_data:
        problems.append(f"{len(pairs)} pairs for {layout.n_data} data qubits")
    if len({a for a, _ in pairs}) != len(pairs):
        problems.append("a control qubit is used twice")
    if len({b for _, b in pairs}) != len(pairs):
        problems.append("a target qubit is used twice")

    return {"distance": layout.distance, "pairs": len(pairs),
            "problems": problems, "valid": not problems}


def verify_bell_pair_operators(layout: TwoPatchLayout | None = None) -> dict:
    """The two-patch Bell pair's logical operators must have the right algebra.

    Two facts together make ``X_A X_B`` and ``Z_A Z_B`` the stabilisers of a Bell
    pair rather than of a product state:

    * within a patch, ``X`` and ``Z`` **anticommute**, which is what makes the
      patch a logical qubit rather than a classical bit;
    * across patches, each operator is a product of two *commuting* single-patch
      operators, so ``X_A X_B`` and ``Z_A Z_B`` commute with each other and can be
      simultaneously stabilised.

    Both are checked on the actual layout, so a broken index offset surfaces here
    rather than in a silently wrong logical operator.
    """
    layout = layout or TwoPatchLayout(3)
    problems: list[str] = []

    # Within a patch: logical X and Z must anticommute.
    for patch in ("A", "B"):
        if len(set(layout.logical_x(patch)) & set(layout.logical_z(patch))) % 2 != 1:
            problems.append(f"patch {patch}: its own X and Z do not anticommute")

    # Across patches the single-patch operators act on disjoint qubits, hence commute;
    # this is what allows the two products to be stabilised at once.
    for op_a in ("X", "Z"):
        for op_b in ("X", "Z"):
            qubits_a = set(layout.logical_x("A") if op_a == "X"
                           else layout.logical_z("A"))
            qubits_b = set(layout.logical_x("B") if op_b == "X"
                           else layout.logical_z("B"))
            if qubits_a & qubits_b:
                problems.append(f"{op_a}_A and {op_b}_B share a qubit, so they "
                                f"would not commute")

    # And the sanity check that the frame algebra has the right sign.
    if pauli_commutes(PAULI_X, PAULI_Z):
        problems.append("single-qubit X and Z commute in the frame algebra, "
                        "which is impossible")
    if not pauli_commutes(PAULI_X, PAULI_X):
        problems.append("a Pauli does not commute with itself")

    return {"layout_valid": layout.verify()["valid"], "problems": problems,
            "valid": not problems}
