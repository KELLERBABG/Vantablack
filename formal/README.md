# Formal protocol models

Four ProVerif files. They are the artifact CI runs (`formal-model` job), so they
are also the whole of what "formally verified" means for this repository: a
claim that is not a query in these files has not been checked by a prover.

## Run

```bash
proverif formal/ghost_session.pv
proverif formal/session_ratchet.pv
proverif formal/shardsec_space_time.pv
proverif formal/ghost_circuit_unlinkability.pv
```

ProVerif 2.05 is what CI builds and runs. A successful run is the only evidence
that a query holds; the expectations below are what the models are written to
establish, not a substitute for running them.

### Reading a reachability query

`query event(e).` is a **reachability** query. ProVerif reports a reachable
event as `RESULT event(e) is false` — it failed to prove unreachability and
printed a trace. Each of the first three files therefore ends with a positive
witness:

| File | Witness | Meaning if it prints `true` |
|---|---|---|
| `ghost_session.pv` | `event(agreement(a, b))` | the handshake never completes; every secrecy query is vacuous |
| `session_ratchet.pv` | `event(epoch2_complete())` | the epoch-2 ratchet never completes; the PCS query is vacuous |
| `ghost_circuit_unlinkability.pv` | `event(exit_matched_origin())` | the exit never opens a cell; the circuit queries are vacuous |

CI fails the job if the unreachability summary appears for those events.

## ghost_session.pv

Both roles are separate replicated processes with their own secrets, over one
public channel, against an active Dolev-Yao attacker that holds every public key.

What changed in v2.1.8, and why the previous file could not support its own
claims:

- **Diffie-Hellman commutativity is an equation.** Without
  `dh(x, dh(y, g)) = dh(y, dh(x, g))`, initiator and responder derived
  different keys on every run. Nothing could ever be decrypted, so every
  secrecy query passed for the wrong reason.
- **The KEM ciphertext is transmitted.** The initiator encapsulates to the
  responder's public key and sends the ciphertext; the responder decapsulates it
  with `skPQb`. The earlier file had each side "decapsulate" a ciphertext it had
  itself encapsulated to the other side's key, so the two post-quantum secrets
  were never the same value.
- **A reachability witness proves the protocol executes.**

Under that attacker the file queries:

1. **Secrecy of the payload** (`attacker(payload)`). The key itself is not a
   free name: it is derived from the two ephemeral secrets, so a query on it
   would be a query on a value no rule can ever produce.
2. **Agreement.** `inj-event(agreement(a, b)) ==> inj-event(resp_started(a, b))`:
   the initiator accepts only for a session a responder started with the very key
   the initiator signed.
3. **Replay.** `inj-event(recv_counter(a, cnt)) ==> inj-event(sent_counter(a, cnt))`:
   every counter the responder accepts was emitted by the initiator.
4. **Reachability.** `event(agreement(a, b))` is reachable.

## session_ratchet.pv

Two communicating peers, not one straight-line process.

- Both derive epoch 0 from one pre-shared root `psk`; epoch 0 seals `m0_fs`,
  steps `ck0 -> ck1`, and discards `ck0`.
- The adversary is handed `rk1` and `ck1` on `c`.
- Epoch 2 is an authenticated hybrid ratchet: fresh classical shares on both
  sides, a fresh KEM keypair from the responder, an encapsulation from the
  initiator transmitted on `c`, and signatures over the transcript.
- `attacker(m0_fs)` checks forward secrecy after the epoch-0 chain step.
- `attacker(m2_pcs)` checks that `(rk1, ck1)` does not compromise epoch 2 once
  the authenticated hybrid step completes.
- `event(epoch0_sealed())` and `event(epoch2_complete())` are the reachability
  witnesses.

## ghost_circuit_unlinkability.pv

Three parallel scenarios with different assumptions:

1. **Compromised entry relay only** (`k_r1` published): payload, exit
   destination and origin identity stay secret. `origin_id` is used to derive an
   opaque reply tag `h(origin_id, k_exit)`; the exit routes by tag and never sees
   the identity.
2. **Entry *and* middle compromised** (`k_r1`, `k_r2` published): the honest
   loss is that the middle relay learns and links the next hop
   (`event(middle_linked_exit(hop_exit))` is reachable). The payload, exit
   destination and origin identity remain secret because the exit layer is still
   under `k_exit`.
3. **Observational equivalence** (`diff(wire_a, wire_b)`): two first-hop onions
   that differ only in the origin identity are indistinguishable to the
   adversary. This is the unlinkability claim in its weakest checkable form.

## shardsec_space_time.pv

Unchanged. It asserts exactly one thing: an attacker holding **one** sealed
shard and the key for it learns nothing about the payload behind the other two.

Its ceiling is the idealisation. The three Reed-Solomon shards are uninterpreted
function applications rather than GF(2^8) linear combinations, so the file says
nothing about the real code. The real `(c, r, f)` ramp bound is exercised by
`cargo test --lib l4_rs` (any `r + c` shards reconstruct, fewer do not, duplicate
indices do not count), which is a test, not a proof.

## What none of these establish

- No reduction for the signature, KEM or AEAD primitives. They are ideal.
- Nothing about wire format: cell sizes, padding, length uniformity or timing.
- Nothing about the Rust implementation matching the model. The models are a
  description of intent; the code is the artifact that ships.
- Forward secrecy or post-compromise security outside `session_ratchet.pv`.
- Key-compromise impersonation, unknown-key-share attacks, or multi-session
  state beyond what the replicated processes express.

A successful run is a symbolic result about these abstractions. It does not
replace Rust tests, implementation review, or traffic-analysis experiments.
