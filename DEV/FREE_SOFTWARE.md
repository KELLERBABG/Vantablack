# Free software — no license gate, no payments

Vantablack is free and open-source software, distributed under the
[MIT License](LICENSE).

Every capability a build contains is available to everyone who has that build:

- **No activation.** No license key, no redeem code, no account, and no vendor
  key compiled into any binary.
- **No gate.** Nothing checks an entitlement at startup or at runtime, and no
  code path refuses to start, refuses to connect, or refuses to carry traffic
  because of licensing state.
- **No vendor service.** The product makes no call to a licensing, activation or
  payment service.
- **No billing.** No checkout, subscription, trial expiry or metering.

If a build ever refuses to work for a licensing reason, that is not this source
tree — please report it as a bug.

---

Earlier in this checkout an exploration of a licensing and payment layer was
developed (an entitlement module, two vendor binaries, their test suites, and two
documents describing them). That work, and the documents, have been **removed**:
they described a product this project is not. The scratch scripts from that
exploration are gone too.
