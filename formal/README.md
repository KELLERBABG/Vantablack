# Formal protocol models

Two ProVerif files. They are the artifact CI runs (`formal-model` job), so they
are also the whole of what "formally verified" means for this repository: a
claim that is not a query in these files has not been checked by a prover.

## Run

```bash
proverif formal/ghost_session.pv
proverif formal/shardsec_space_time.pv
```

Both were run against ProVerif 2.05. `ghost_session.pv` reports all four queries
true; `shardsec_space_time.pv` reports `not attacker(secret_payload[]) is true`.
The CI `formal-model` job builds ProVerif from source and runs the same two
commands.

## ghost_session.pv: what it establishes

Both roles run as separate replicated processes with their own secrets, over one
public channel, against an active Dolev-Yao attacker that holds every public key.
Under that attacker the file queries:

1. **Secrecy of the payload and of the message key.** The attacker cannot derive
   either.
2. **Agreement.** `inj-event(agreement(a, b)) ==> inj-event(resp_started(a, b))`:
   the initiator accepts only for a session a responder started with the very key
   the initiator signed. The responder's event carries the material it
   authenticated, so the query is not satisfied by a responder that started with
   some other key.
3. **Replay.** `inj-event(recv_counter(a, cnt)) ==> inj-event(sent_counter(a, cnt))`:
   every counter the responder accepts was emitted by the initiator.

Both a positive control and the limit of the negative side were checked by hand
with ProVerif 2.05:

- **Positive control.** A variant that publishes the private value to the
  attacker reports the query false, and the same query run against a message
  carrying only a public value reports it false for that value too. The prover
  is not answering true unconditionally.
- **No failing witness exists here for the agreement query.** Four deliberate
  mutations were tried, including removing the transcript check, replacing it
  with `true`, and widening the responder's event to include a key the initiator
  never signed. All four still report the query true. The reason is structural:
  both roles are single straight-line processes, so no attacker-controlled
  substitution survives to the initiator's accept, and the query cannot separate
  a genuine handshake from a substituted one. The query is therefore a statement
  about what the model can reach, not a demonstrated downgrade test.

## ghost_session.pv: what it does not establish

The model is deliberately small, and none of the following is a query, so none
of it is proven:

- **Forward secrecy and post-compromise security.** Neither long-term key is ever
  revealed to the attacker, so nothing here speaks to what a later compromise of
  a signing key would or would not expose.
- **The ratchet and the hybrid binding.** Each role derives one key from the pair
  (classical, post-quantum) and seals with it. The per-epoch ratchet, the
  prepared-versus-installed epoch state and the transcript-bound derivation are
  not modelled; in particular the file does not show that breaking one family
  alone fails to break the key, which is a property of the real derivation and
  not of this term.
- **Key-compromise impersonation and unknown-key-share attacks.** Signatures are
  ideal and bind the transcript; the binding is asserted, not derived from an
  Ed25519 or ML-DSA reduction.
- **Group, relay, onion and multi-hop behaviour**, including the `RLY!` path.
- **Anything about the wire format.** Length uniformity, padding and the keyed
  jitter tail are properties of the encoder, not of this process calculus.

## shardsec_space_time.pv: what it establishes, and its ceiling

The file asserts exactly one thing: an attacker holding **one** sealed shard and
the key for it learns nothing about the secret payload behind the other two.

Its ceiling is the idealisation, and it is a low one. The three Reed-Solomon
shards are uninterpreted function applications rather than GF(2^8) linear
combinations, so the file says nothing about the real erasure code. The model has
no notion of *which* two of three shards an attacker holds, so it does not
demonstrate the threshold property the README and `docs/SOTA.md` describe.
Raising it to that standard means encoding the two-of-three structure, and until
that is done the files above are the accurate description of the guarantee.

## Standing

A successful run is a symbolic result about these abstractions. It does not
replace Rust tests, implementation review, or traffic-analysis experiments.
