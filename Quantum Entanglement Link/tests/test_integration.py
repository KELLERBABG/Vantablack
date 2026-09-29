import numpy as np
from quantumnet.core import QubitState, apply, X, Z
from quantumnet.protocols import (
    run_teleportation, run_superdense, run_swapping,
    shor_encode, shor_correct, shor_decode, shor_syndrome,
    steane_encode, steane_correct, steane_decode, steane_syndrome,
    bbssw_distill, deutsch_distill, prepare_noisy_bell_pairs,
    apply_t1_t2_noise, memory_cutoff_time, QuantumMemoryBuffer,
)


class TestEncodeCorrectDecode:
    def test_shor_all_single_errors_zero(self):
        orig = QubitState.zero()
        for qi in range(9):
            for gate in (X, Z):
                enc = shor_encode(orig)
                noisy = apply(gate, enc, targets=[qi])
                corrected = shor_correct(noisy)
                dec = shor_decode(corrected)
                assert orig.fidelity(dec) > 0.99, f"Shor zero {gate} on q{qi}"

    def test_shor_all_single_errors_plus(self):
        orig = QubitState.plus()
        for qi in range(9):
            enc = shor_encode(orig)
            noisy = apply(X, enc, targets=[qi])
            corrected = shor_correct(noisy)
            dec = shor_decode(corrected)
            assert orig.fidelity(dec) > 0.99, f"Shor plus X on q{qi}"

    def test_steane_all_single_errors_zero(self):
        orig = QubitState.zero()
        for qi in range(7):
            for gate in (X, Z):
                enc = steane_encode(orig)
                noisy = apply(gate, enc, targets=[qi])
                corrected = steane_correct(noisy)
                dec = steane_decode(corrected)
                assert orig.fidelity(dec) > 0.99, f"Steane zero {gate} on q{qi}"

    def test_steane_all_single_errors_plus(self):
        orig = QubitState.plus()
        for qi in range(7):
            enc = steane_encode(orig)
            noisy = apply(X, enc, targets=[qi])
            corrected = steane_correct(noisy)
            dec = steane_decode(corrected)
            assert orig.fidelity(dec) > 0.99, f"Steane plus X on q{qi}"


class TestDistillation:
    def test_bbssw_perfect(self):
        ideal = QubitState.bell_phi_plus()
        result = bbssw_distill(ideal, ideal, rng=np.random.default_rng(42))
        assert result["success"]

    def test_deutsch_perfect(self):
        ideal = QubitState.bell_phi_plus()
        result = deutsch_distill(ideal, ideal, rng=np.random.default_rng(42))
        assert result["success"]

    def test_distillation_noisy_improves(self):
        rng = np.random.default_rng(42)
        pairs = prepare_noisy_bell_pairs(10, fidelity=0.7, rng=rng)
        for func in (bbssw_distill, deutsch_distill):
            for i in range(len(pairs) // 2):
                result = func(pairs[2 * i], pairs[2 * i + 1], rng=rng)
                if result["success"]:
                    assert result["distilled_fidelity"] >= 0.6


class TestMemory:
    def test_t1_decay_one(self):
        decayed = apply_t1_t2_noise(QubitState.one(), t=1.0, t1=1.0, t2=1000.0)
        assert decayed.purity() < 1.0
        assert 0 < decayed.rho[0, 0] < 1

    def test_cutoff_time_reasonable(self):
        t_cut = memory_cutoff_time(QubitState.one(), t1=10.0, t2=10.0, threshold=0.5)
        assert 5.0 < t_cut < 10.0

    def test_buffer_drops_after_cutoff(self):
        buf = QuantumMemoryBuffer(t1=2.0, t2=2.0, cutoff_fidelity=0.5)
        buf.store("q1", QubitState.one(), current_time=0.0)
        assert buf.retrieve("q1", current_time=20.0) is None

    def test_buffer_keeps_before_cutoff(self):
        buf = QuantumMemoryBuffer(t1=100.0, t2=100.0, cutoff_fidelity=0.5)
        buf.store("q1", QubitState.one(), current_time=0.0)
        assert buf.retrieve("q1", current_time=1.0) is not None


class TestErrorSync:
    def test_shor_syndrome_after_correct_is_zero(self):
        enc = shor_encode(QubitState.zero())
        noisy = apply(X, enc, targets=[5])
        corrected = shor_correct(noisy)
        assert shor_syndrome(corrected) == [0] * 8

    def test_steane_syndrome_after_correct_is_zero(self):
        enc = steane_encode(QubitState.zero())
        noisy = apply(Z, enc, targets=[4])
        corrected = steane_correct(noisy)
        assert steane_syndrome(corrected) == [0] * 6


class TestProtocolEndToEnd:
    def test_teleport_fidelity(self):
        r = run_teleportation(rng=np.random.default_rng(42))
        assert r["teleported_fidelity"] > 0.99

    def test_superdense_roundtrip(self):
        for msg in range(4):
            r = run_superdense(bits=msg, rng=np.random.default_rng(42 + msg))
            assert r["success"]
            assert r["decoded_bits"] == f"{msg:02b}"

    def test_swapping_no_noise(self):
        r = run_swapping(noise=0.0, rng=np.random.default_rng(42))
        assert r["swapped_fidelity"] > 0.99
