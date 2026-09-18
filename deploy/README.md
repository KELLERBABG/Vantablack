# Vantablack — Deploy-Not-Design Reference Testbed (§48)

This directory provides a reproducible 3-node in-container reference mesh for validating the daemon under realistic carrier conditions.

## Overview

The reference deployment creates a reproducible 3-node in-container mesh:
- **Hub (`mesh-hub`)**: Runs daemon in hub/exit role with Proof-of-Work anti-abuse (§50), Dead-Drop Vault (§22, §33), and DTN State Reconciliation (§29).
- **Relay (`mesh-relay`)**: Runs blind forwarder with Anonymous Capability Ledger (§45) and Sphinx-Shard onion transit (§8).
- **Client (`mesh-client`)**: Runs edge daemon dispatching RS(2,1) shards across diffusion routes (§32) and Spatio-Temporal Erosion coding (§27).

## Quickstart

```bash
# 1. Start reference network
docker compose up -d

# 2. Run automated validation smoke test
./smoke_test.sh

# 3. Teardown
docker compose down
```
