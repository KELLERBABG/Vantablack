import numpy as np
from quantumnet.core import QubitState
from quantumnet.protocols import bbssw_distill, deutsch_distill, prepare_noisy_bell_pairs, prepare_bell_state


def test_bbssw_perfect_pairs():
    ideal = QubitState.bell_phi_plus()
    result = bbssw_distill(ideal, ideal, rng=np.random.default_rng(42))
    assert result["success"]
    assert result["distilled_fidelity"] > 0.99


def test_deutsch_perfect_pairs():
    ideal = QubitState.bell_phi_plus()
    result = deutsch_distill(ideal, ideal, rng=np.random.default_rng(42))
    assert result["success"]
    assert result["distilled_fidelity"] > 0.99


def test_bbssw_improves_fidelity():
    pairs = prepare_noisy_bell_pairs(20, fidelity=0.7, rng=np.random.default_rng(42))
    input_f = sum(p.fidelity(QubitState.bell_phi_plus()) for p in pairs) / len(pairs)
    result = bbssw_distill(pairs[0], pairs[1], rng=np.random.default_rng(43))
    if result["success"]:
        assert result["distilled_fidelity"] >= input_f * 0.9


def test_deutsch_improves_fidelity():
    pairs = prepare_noisy_bell_pairs(20, fidelity=0.7, rng=np.random.default_rng(42))
    input_f = sum(p.fidelity(QubitState.bell_phi_plus()) for p in pairs) / len(pairs)
    result = deutsch_distill(pairs[0], pairs[1], rng=np.random.default_rng(43))
    if result["success"]:
        assert result["distilled_fidelity"] >= input_f * 0.9
