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
const SLOT_GET_PATH_RE = /^\/v2\/slot\/([0-9a-fA-F]{64})$/;
const SLOT_PUT_PATH_RE = /^\/v2\/slot\/([0-9a-fA-F]{64})\/([0-9a-fA-F]{16,64})$/;
const POW_HEADER = "x-vb-pow";
const POW_NONCE_HEX_RE = /^[0-9a-fA-F]{16}$/;

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

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function verifyPow(slotHex, ephemeralId, nonceHex, bodyBytes) {
  if (!nonceHex || !POW_NONCE_HEX_RE.test(nonceHex)) {
    return false;
  }
  const prefix = new TextEncoder().encode(`${slotHex}:${ephemeralId}:`);
  const nonceBytes = hexToBytes(nonceHex);
  const input = new Uint8Array(prefix.length + nonceBytes.length + bodyBytes.length);
  input.set(prefix, 0);
  input.set(nonceBytes, prefix.length);
  input.set(bodyBytes, prefix.length + nonceBytes.length);

  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
  // 16-bit PoW: first 2 bytes must be zero.
  return digest[0] === 0 && digest[1] === 0;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (
      request.method === "GET" &&
      (url.pathname === "/health" || url.pathname === "/v1/health" || url.pathname === "/v2/health")
    ) {
      return jsonResponse({ status: "ok" }, 200);
    }

    if (!env || !env.BLIND_SLOTS) {
      return jsonResponse({ error: "BLIND_SLOTS KV binding not configured" }, 500);
    }

    if (request.method === "GET") {
      const match = SLOT_GET_PATH_RE.exec(url.pathname);
      if (!match) {
        return jsonResponse({ error: "not found" }, 404);
      }

      const slotHex = match[1].toLowerCase();
      const prefix = `slot:${slotHex}:`;
      const listed = await env.BLIND_SLOTS.list({ prefix, limit: MAX_ENTRIES_PER_SLOT });
      const values = await Promise.all(
        listed.keys.map((key) => env.BLIND_SLOTS.get(key.name, "text")),
      );
      const blobs = values.filter((entry) => typeof entry === "string" && entry.length > 0);
      return jsonResponse(blobs, 200);
    }

    if (request.method === "PUT") {
      const match = SLOT_PUT_PATH_RE.exec(url.pathname);
      if (!match) {
        return jsonResponse({ error: "not found" }, 404);
      }

      const slotHex = match[1].toLowerCase();
      const ephemeralId = match[2].toLowerCase();

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

      const bodyBytes = new Uint8Array(buf);
      const powHeader = request.headers.get(POW_HEADER);
      const powValid = await verifyPow(slotHex, ephemeralId, powHeader, bodyBytes);
      if (!powValid) {
        return jsonResponse({ error: "invalid or missing X-VB-PoW" }, 403);
      }

      const encoded = bytesToBase64(bodyBytes);
      const subkey = `slot:${slotHex}:${ephemeralId}`;
      await env.BLIND_SLOTS.put(subkey, encoded, {
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
