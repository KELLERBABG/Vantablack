# Operational Guide: Zero-Cost Peer Discovery

This guide provides step-by-step instructions for establishing a decentralized peer mesh without paying for hosted virtual private servers (VPS).

---

## 1. Cloudflare DNS Seed Configuration

Vantablack uses standard DNS `A` and `AAAA` record resolution to discover active peer IP addresses. Cloudflare provides fast, free, worldwide anycast DNS that serves as an ideal bootstrap mechanism.

### Step 1: Add DNS Record in Cloudflare
1. Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com).
2. Select your domain and navigate to **DNS** &rarr; **Records**.
3. Click **Add record**:
   - **Type:** `A`
   - **Name:** `seeds` (or whatever subdomain you prefer, e.g. `seeds.yourdomain.com`).
   - **IPv4 address:** Enter the public IP of your primary node or exit node.
   - **Proxy status:** **DNS only (Grey Cloud)**.  
     *(Important: Do NOT enable the orange cloud proxy. Cloudflare’s HTTP reverse proxy does not forward raw UDP mesh packets).*
   - **TTL:** Auto or 2 minutes.

### Step 2: Multi-Peer Round-Robin (Optional)
To provide redundancy across multiple peer nodes, create additional `A` records with the same name (`seeds`) pointing to the IP addresses of other friend or exit nodes. When new nodes query the subdomain, Cloudflare returns all IP addresses via DNS round-robin.

---

## 2. Configuring Node Launchers

In your `config.env` file, uncomment and specify your DNS seed:

```env
# Cloudflare DNS Seed hostname and mesh port
GHOST_DNS_SEED=seeds.yourdomain.com:2270
```

When you start a node (the `.bat` launchers were removed in 19b1ef1 - run the binary directly):
1. The node issues an asynchronous DNS query for `seeds.yourdomain.com`.
2. It discovers the active peer IP addresses.
3. It performs a post-quantum handshake and joins the mesh.

---

## 3. Dynamic Local Peer Cache (`peers.cache`)

Once a node successfully connects to peers:
- Active peer addresses are automatically written to `peers.cache` on the local file system.
- If your computer reboots or is temporarily without DNS access, Vantablack loads `peers.cache` first, attempting immediate direct peer reconnects before polling DNS seeds.
- This creates an offline-first, resilient network that survives DNS outages and ISP-level DNS tampering.
