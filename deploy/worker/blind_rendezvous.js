/**
 * Vantablack — Zero-Knowledge Blind Mailbox Rendezvous Worker
 *
 * Self-hostable Cloudflare Worker providing ephemeral, fixed-size encrypted
 * rendezvous slots. The worker never sees plaintext IPs, node fingerprints,
 * Ed25519 keys, or swarm graphs — only 32-byte slot hashes and opaque
 * ChaCha20-Poly1305 ciphertexts (<= 1024 bytes, TTL 900s).
 *
 * Privacy invariant: ZERO IP, header, slot, or payload logging.
 */

const MAX_BODY_BYTES = 1024;
const SLOT_TTL_SECS = 900;
const MAX_ENTRIES_PER_SLOT = 32;
const SLOT_PATH_RE = /^\/v1\/slot\/([0-9a-fA-F]{64})$/;

const COMMON_HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...COMMON_HEADERS,
      "Content-Type": "application/json",
    },
  });
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && (url.pathname === "/health" || url.pathname === "/v1/health")) {
      return jsonResponse({ status: "ok" }, 200);
    }

    const match = SLOT_PATH_RE.exec(url.pathname);
    if (!match) {
      return jsonResponse({ error: "not found" }, 404);
    }

    if (!env || !env.BLIND_SLOTS) {
      return jsonResponse({ error: "BLIND_SLOTS KV binding not configured" }, 500);
    }

    const slotKey = `slot:${match[1].toLowerCase()}`;

    if (request.method === "GET") {
      const stored = await env.BLIND_SLOTS.get(slotKey, "json");
      const blobs = Array.isArray(stored)
        ? stored.filter((entry) => typeof entry === "string")
        : [];
      return jsonResponse(blobs, 200);
    }

    if (request.method === "PUT") {
      const contentLengthHeader = request.headers.get("content-length");
      if (contentLengthHeader !== null) {
        const declaredLen = Number(contentLengthHeader);
        if (Number.isFinite(declaredLen) && declaredLen > MAX_BODY_BYTES) {
          return jsonResponse({ error: "payload too large" }, 413);
        }
      }

      const buf = await request.arrayBuffer();
      if (buf.byteLength === 0) {
        return jsonResponse({ error: "empty payload" }, 400);
      }
      if (buf.byteLength > MAX_BODY_BYTES) {
        return jsonResponse({ error: "payload too large" }, 413);
      }

      const encoded = bytesToBase64(new Uint8Array(buf));
      const existingRaw = await env.BLIND_SLOTS.get(slotKey, "json");
      const bucket = Array.isArray(existingRaw)
        ? existingRaw.filter((entry) => typeof entry === "string")
        : [];

      const deduped = bucket.filter((entry) => entry !== encoded);
      deduped.push(encoded);
      if (deduped.length > MAX_ENTRIES_PER_SLOT) {
        deduped.splice(0, deduped.length - MAX_ENTRIES_PER_SLOT);
      }

      await env.BLIND_SLOTS.put(slotKey, JSON.stringify(deduped), {
        expirationTtl: SLOT_TTL_SECS,
      });

      return new Response(null, {
        status: 204,
        headers: COMMON_HEADERS,
      });
    }

    return new Response(null, {
      status: 405,
      headers: {
        ...COMMON_HEADERS,
        Allow: "GET, PUT",
      },
    });
  },
};
