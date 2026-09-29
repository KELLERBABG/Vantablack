import numpy as np
from ..core import QubitState


def apply_t1_t2_noise(state, t, t1, t2):
    rho = state.rho.copy()
    if t1 > 0:
        p = 1 - np.exp(-t / t1)
        rho[0, 0] = rho[0, 0] + p * rho[1, 1]
        rho[1, 1] = rho[1, 1] * (1 - p)
        rho[0, 1] = rho[0, 1] * np.sqrt(1 - p)
        rho[1, 0] = rho[1, 0] * np.sqrt(1 - p)
    if t2 > 0:
        p = 1 - np.exp(-t / t2)
        rho[0, 1] = rho[0, 1] * (1 - p)
        rho[1, 0] = rho[1, 0] * (1 - p)
    return QubitState(rho, dims=state.dims)


def memory_fidelity_over_time(initial_state, times, t1, t2):
    return [initial_state.fidelity(apply_t1_t2_noise(initial_state, t, t1, t2)) for t in times]


def memory_cutoff_time(initial_state, t1, t2, threshold=0.5):
    lo, hi = 0.0, max(t1, t2) * 10 if t1 > 0 or t2 > 0 else 100.0
    for _ in range(50):
        mid = (lo + hi) / 2
        fid = initial_state.fidelity(apply_t1_t2_noise(initial_state, mid, t1, t2))
        if fid >= threshold:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


class QuantumMemoryBuffer:
    def __init__(self, t1=100.0, t2=50.0, cutoff_fidelity=0.5):
        self.t1 = t1
        self.t2 = t2
        self.cutoff_fidelity = cutoff_fidelity
        self._slots = {}

    def store(self, key, state, current_time=0.0):
        self._slots[key] = (state, current_time)

    def retrieve(self, key, current_time):
        if key not in self._slots:
            return None
        state, stored_at = self._slots[key]
        dt = current_time - stored_at
        decayed = apply_t1_t2_noise(state, dt, self.t1, self.t2)
        if state.fidelity(decayed) < self.cutoff_fidelity:
            del self._slots[key]
            return None
        return decayed

    def clear(self):
        self._slots.clear()
