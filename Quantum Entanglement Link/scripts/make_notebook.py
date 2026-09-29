import nbformat as nbf

nb = nbf.v4.new_notebook()
nb.metadata = {
    'kernelspec': {'display_name': 'Python 3', 'language': 'python', 'name': 'python3'},
    'language_info': {'name': 'python', 'version': '3.14.2'}
}

cells = []

def md(s):
    cells.append(nbf.v4.new_markdown_cell(s))
def code(s):
    cells.append(nbf.v4.new_code_cell(s))

md("# Quantum Entanglement Link -- Interactive Demo\n\nA simulation-first quantum communication network stack in Python.\nDensity matrix formalism throughout, explicit noise everywhere.")

md("## 1. Core Primitives\n\n### Bell states, fidelity, purity, concurrence")

code("import numpy as np\nfrom quantumnet.core import QubitState, apply, H, CNOT, X, Z, measure\nfrom quantumnet.protocols import *\n\nnp.set_printoptions(precision=4, suppress=True)\nrng = np.random.default_rng(42)")

code("phi_plus = QubitState.bell_phi_plus()\nprint(f'|Phi+> purity: {phi_plus.purity():.4f}')\nprint(f'|Phi+> concurrence: {phi_plus.concurrence():.4f}')\nprint(f'|Phi+> rho diagonal:\\n{np.diag(phi_plus.rho)}')")

code("# Fidelity between Bell states\nphi_minus = QubitState.bell_phi_minus()\npsi_plus = QubitState.bell_psi_plus()\nprint(f'<Phi+|Phi-> = {phi_plus.fidelity(phi_minus):.4f}')\nprint(f'<Phi+|Psi+> = {phi_plus.fidelity(psi_plus):.4f}')")

md("## 2. QKD Protocols")

code("print('=== BB84 QKD ===')\nr = run_bb84(512, noise=0.01, rng=rng)\nprint(f'Key length: {len(r[\"key\"])} bits')\nprint(f'QBER:       {r[\"qber\"]:.4f}')\nprint(f'Key prefix: {r[\"key\"][:32]}')")

code("print('=== E91 QKD ===')\nr = run_e91(512, noise=0.01, rng=rng)\nprint(f'Key length: {len(r[\"key\"])} bits')\nprint(f'QBER:       {r[\"qber\"]:.4f}')\nprint(f'CHSH S:     {r[\"s_value\"]:.4f} (violation if > 2)')\nprint(f'Key prefix: {r[\"key\"][:32]}')")

code("# QBER vs noise scan\nprint('QBER vs depolarizing noise:')\nfor noise in [0.0, 0.02, 0.05, 0.1, 0.15]:\n    r = run_bb84(1024, noise=noise, rng=rng)\n    print(f'  noise={noise:.2f} -> QBER={r[\"qber\"]:.4f}, key={len(r[\"key\"])} bits')")

md("## 3. Quantum Teleportation")

code("print('=== Teleportation ===')\nr = run_teleportation(rng=rng)\nprint(f'Input state fidelity:  {r[\"input_fidelity\"]:.6f}')\nprint(f'Teleported fidelity:   {r[\"teleported_fidelity\"]:.6f}')\nprint(f'Bell outcome:          {r[\"bell_outcome\"]}')\nprint(f'Success:               {r[\"success\"]}')")

md("## 4. Superdense Coding")

code("print('=== Superdense Coding ===')\nfor msg in range(4):\n    r = run_superdense(bits=msg, rng=rng)\n    ok = 'OK' if r['success'] else 'FAIL'\n    print(f'  {msg:02b} -> {r[\"decoded_bits\"]}  {ok}')")

md("## 5. Entanglement Swapping")

code("print('=== Entanglement Swapping ===')\nr = run_swapping(noise=0.0, rng=rng)\nprint(f'Noiseless: bell_outcome={r[\"bell_outcome\"]}, fidelity={r[\"swapped_fidelity\"]:.6f}')\nfor noise in [0.05, 0.1, 0.2]:\n    r = run_swapping(noise=noise, rng=rng)\n    print(f'  noise={noise}: fidelity={r[\"swapped_fidelity\"]:.6f}')")

md("## 6. Shor 9-Qubit Error Correction")

code("print('=== Shor 9-qubit Code ===')\nfor state_fn, label in [(QubitState.zero, 'zero'), (QubitState.plus, 'plus')]:\n    orig = state_fn()\n    enc = shor_encode(orig)\n    print(f'{label}: encoded purity={enc.purity():.4f}')\n    for qi in [0, 4, 8]:\n        noisy = apply(X, enc, targets=[qi])\n        corrected = shor_correct(noisy)\n        dec = shor_decode(corrected)\n        fid = orig.fidelity(dec)\n        print(f'  X error on q{qi} -> corrected, fid={fid:.6f}')\n        noisy = apply(Z, enc, targets=[qi])\n        corrected = shor_correct(noisy)\n        dec = shor_decode(corrected)\n        fid = orig.fidelity(dec)\n        print(f'  Z error on q{qi} -> corrected, fid={fid:.6f}')")

md("## 7. Steane [[7,1,3]] Error Correction")

code("print('=== Steane 7-qubit Code ===')\nfor state_fn, label in [(QubitState.zero, 'zero'), (QubitState.plus, 'plus')]:\n    orig = state_fn()\n    enc = steane_encode(orig)\n    print(f'{label}: encoded purity={enc.purity():.4f}')\n    for qi in [0, 3, 6]:\n        noisy = apply(X, enc, targets=[qi])\n        corrected = steane_correct(noisy)\n        dec = steane_decode(corrected)\n        fid = orig.fidelity(dec)\n        print(f'  X error on q{qi} -> corrected, fid={fid:.6f}')\n        noisy = apply(Z, enc, targets=[qi])\n        corrected = steane_correct(noisy)\n        dec = steane_decode(corrected)\n        fid = orig.fidelity(dec)\n        print(f'  Z error on q{qi} -> corrected, fid={fid:.6f}')")

md("## 8. Entanglement Distillation")

code("print('=== BBPSSW Distillation ===')\npairs = prepare_noisy_bell_pairs(10, fidelity=0.75, rng=rng)\nprint(f'Input pairs: {len(pairs)}, target fidelity=0.75')\nfor i in range(len(pairs) // 2):\n    result = bbssw_distill(pairs[2*i], pairs[2*i+1], rng=rng)\n    if result['success']:\n        print(f'  Pair {i}: success, distilled fid={result[\"distilled_fidelity\"]:.4f}')")

code("print('=== Deutsch Distillation ===')\npairs = prepare_noisy_bell_pairs(10, fidelity=0.75, rng=rng)\nfor i in range(len(pairs) // 2):\n    result = deutsch_distill(pairs[2*i], pairs[2*i+1], rng=rng)\n    if result['success']:\n        print(f'  Pair {i}: success, distilled fid={result[\"distilled_fidelity\"]:.4f}')")

md("## 9. Quantum Memory Buffer (T1/T2 Decoherence)")

code("print('=== T1/T2 Memory ===')\nstate = QubitState.one()\nprint(f'Initial state: |1>, T1=10, T2=10')\nfor t in [0, 2, 5, 10, 20]:\n    noisy = apply_t1_t2_noise(state, t=t, t1=10.0, t2=10.0)\n    fid = state.fidelity(noisy)\n    pop_0 = noisy.rho[0,0]\n    print(f'  t={t:3d}: fidelity={fid:.4f}, population|0>={pop_0:.4f}')")

code("print('=== Cutoff Time ===')\nstate = QubitState.one()\nt_cut = memory_cutoff_time(state, t1=10.0, t2=10.0, threshold=0.5)\nprint(f'Cutoff time (threshold=0.5): {t_cut:.4f}')\nbuf = QuantumMemoryBuffer(t1=10.0, t2=10.0, cutoff_fidelity=0.5)\nbuf.store('q1', state, current_time=0.0)\nretrieved = buf.retrieve('q1', current_time=t_cut * 2)\nprint(f'Retrieve after 2x cutoff: {\"dropped\" if retrieved is None else \"kept\"}')")

md("## 10. Full Pipeline: Encode -> Error -> Correct -> Decode")

code("print('=== Shor Code: Full Error Correction Pipeline ===')\nn_errors = 0\nn_corrected = 0\nfor state_fn, label in [(QubitState.zero, '0'), (QubitState.one, '1'), (QubitState.plus, '+')]:\n    for qi in range(9):\n        for gate, gname in [(X, 'X'), (Z, 'Z')]:\n            orig = state_fn()\n            enc = shor_encode(orig)\n            noisy = apply(gate, enc, targets=[qi])\n            corrected = shor_correct(noisy)\n            dec = shor_decode(corrected)\n            fid = orig.fidelity(dec)\n            n_errors += 1\n            if fid > 0.99:\n                n_corrected += 1\n            else:\n                print(f'  FAIL: |{label}> {gname} on q{qi}: fid={fid:.4f}')\nprint(f'Corrected {n_corrected}/{n_errors} single-qubit errors')")

code("print('=== Steane Code: Full Error Correction Pipeline ===')\nn_errors = 0\nn_corrected = 0\nfor state_fn, label in [(QubitState.zero, '0'), (QubitState.one, '1'), (QubitState.plus, '+')]:\n    for qi in range(7):\n        for gate, gname in [(X, 'X'), (Z, 'Z')]:\n            orig = state_fn()\n            enc = steane_encode(orig)\n            noisy = apply(gate, enc, targets=[qi])\n            corrected = steane_correct(noisy)\n            dec = steane_decode(corrected)\n            fid = orig.fidelity(dec)\n            n_errors += 1\n            if fid > 0.99:\n                n_corrected += 1\n            else:\n                print(f'  FAIL: |{label}> {gname} on q{qi}: fid={fid:.4f}')\nprint(f'Corrected {n_corrected}/{n_errors} single-qubit errors')")

md("## Done\n\nAll protocols verified. For CLI usage: `python -m quantumnet all`\n\nTo run this notebook: `jupyter notebook notebooks/demo.ipynb`")

nb.cells = cells
nbf.write(nb, 'notebooks/demo.ipynb')
print('Notebook created: notebooks/demo.ipynb')
