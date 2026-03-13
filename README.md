<div align="center">

```
██╗   ██╗ ██████╗ ██╗  ████████╗███████╗██╗  ██╗
██║   ██║██╔═══██╗██║  ╚══██╔══╝██╔════╝╚██╗██╔╝
██║   ██║██║   ██║██║     ██║   █████╗   ╚███╔╝ 
╚██╗ ██╔╝██║   ██║██║     ██║   ██╔══╝   ██╔██╗ 
 ╚████╔╝ ╚██████╔╝███████╗██║   ███████╗██╔╝ ██╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝
```

**Neural LSM Core · Content-Addressed Memory · Paged Vault · Export Utility**

[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue?style=flat-square&logo=c%2B%2B)](https://en.cppreference.com/w/cpp/17)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-SHA--256-green?style=flat-square)](https://www.openssl.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)]()

</div>

---

## What is Voltex?

Voltex is a **content-addressed, decay-aware memory store** implemented as an interactive C++ command-line system. It ingests arbitrary text strings, shreds them into cryptographic leaf nodes, and assembles them into a **Merkle DAG** where every node's identity is the SHA-256 hash of its children.

Three properties make it distinct from a conventional key-value store:

| Property | Description |
|---|---|
| **Content Addressing** | A string's identity is a deterministic 64-char hex Root ID. Same input always → same ID, forever. |
| **Structural Deduplication** | Two strings sharing a common substring share the actual graph nodes encoding that substring. Storage grows with *unique* content, not ingestion volume. |
| **Vitality Decay** | Every node carries a float vitality. Nodes decay toward zero each DREAM cycle and are purged when they fall below threshold. Pin critical nodes to make them immortal. |

---

## Repository Structure

```
voltex/
├── voltex_paged.cpp     # Live vault — interactive REPL
├── vtx_export.cpp       # Export utility — compact portable snapshots
├── vtx_test.cpp         # Test harness — drives both binaries
└── README.md
```

---

## Quick Start

### Prerequisites

- C++17 compiler (GCC 9+, Clang 10+, MSVC VS2022)
- OpenSSL (required by `voltex_paged.cpp` only)
- [vcpkg](https://vcpkg.io/) recommended for dependency management

### Install OpenSSL via vcpkg

```bash
vcpkg install openssl:x64-windows   # Windows
vcpkg install openssl               # Linux / macOS
vcpkg integrate install
```

### Build

```bash
# Live vault (requires OpenSSL)
g++ -std=c++17 -O2 voltex_paged.cpp -lssl -lcrypto -o voltex

# Export utility (no OpenSSL needed)
g++ -std=c++17 -O2 vtx_export.cpp -o vtx_export

# Test harness (no OpenSSL needed)
g++ -std=c++17 -O2 vtx_test.cpp -o vtx_test
```

> **Windows:** If you get a missing DLL error at runtime, copy `libssl-3-x64.dll` and `libcrypto-3-x64.dll` from `C:/vcpkg/installed/x64-windows/bin/` to your executable directory.

### Run

```bash
./voltex

   ⚚  V O L T E X  ─╼  NEURAL_LSM_CORE  ╾─  P A G E R  ⚚

   [ PULSE: ACTIVE | DEPTH: 0 | POP: 0 | HOT_BLOBS: 0/4096 | LOAD: 0.0% ]

voltex_vault#
```

---

## How It Works

### Ingestion Pipeline

When you call `INGEST` on a string, four phases execute:

```
"hello voltex world"
        │
        ▼
┌───────────────────────────────────────────────┐
│  Phase 1 — Leaf Creation                      │
│  Strings ≤ 4 chars become ATOM nodes.         │
│  HexID = SHA-256(raw text)                    │
│  Existing atoms are revitalized, not duped.   │
└───────────────────────┬───────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────┐
│  Phase 2 — Hebbian Split                      │
│  Find the weakest structural connection point │
│  (lowest vitality product of the two halves). │
│  Tends to split at word and pattern boundaries│
└───────────────────────┬───────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────┐
│  Phase 3 — Merkle Combination                 │
│  CHUNK.HexID = SHA-256(child_a.hash ║ child_b.hash) │
│  Parent identity is entirely determined by    │
│  its children. Any leaf change cascades up.   │
└───────────────────────┬───────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────┐
│  Phase 4 — Dendrite Registration              │
│  Both children record the parent's ID.        │
│  Enables upward traversal for morph surgery.  │
└───────────────────────────────────────────────┘
        │
        ▼
  Root ID: a3f8c2e1d4b79f... (64-char hex)
```

### Paged Memory Model

Voltex splits node data into two layers with different residency policies:

```
┌─────────────────────────────────────────────────────────────┐
│  NodeMeta   →   vault.meta   (ALWAYS IN RAM)                │
│                                                             │
│  • HexID (32 bytes)        • child_a_id, child_b_id        │
│  • vitality (float)        • dendrite list                 │
│  • is_pinned (bool)        • blob_offset (disk pointer)    │
│                                                             │
│  ~120 bytes per node. All graph traversal, decay, and      │
│  morph runs here. Zero disk I/O for DREAM cycles.          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  NodeBlob   →   vault.blob   (DISK, LRU CACHED)             │
│                                                             │
│  • Raw lexeme text (ATOMs only)                            │
│  • Loaded on demand when UNROLL / AUDIT / HUNT needs text  │
│  • LRU cache: default 4096 hot blobs in RAM at once        │
│  • Append-only log — written at ingest, never rewritten    │
└─────────────────────────────────────────────────────────────┘
```

### Vitality and the Dream Cycle

```
Initial vitality: 1.0
Each DREAM cycle: vitality × 0.95
Purge threshold:  0.20

Cycles to purge:  ~32   (0.95³² ≈ 0.19)
Cycles at 40:     ~0.13  (below threshold)

Pinned nodes:  vitality frozen at 1.0, exempt from all decay
```

---

## Command Reference

### Synthesis — Data Entry & Retrieval

| Command | # | Description |
|---|---|---|
| `INGEST` | `1` | Fold a text string into the vault. Prompts for input. Returns a 64-char Root ID. |
| `UNROLL` | `2` | Reconstruct a string from its Root ID. Triggers lazy blob loads. |
| `AUDIT`  | `3` | Print the full Merkle tree topology rooted at a given ID. |
| `HUNT`   | `12` | Probabilistic traversal from a seed. Uses vitality-weighted Top-K sampling. Search by Hex ID or lexeme. |

### Metabolic — Decay & Consolidation

| Command | # | Description |
|---|---|---|
| `DREAM`    | `4`  | Run one decay cycle. Multiplies all unpinned vitalities by 0.95. Purges nodes below 0.2. Zero blob I/O. |
| `EVO`      | `14` | Bulk stress test. Ingests 1000 auto-generated JSON records, auto-pins each root. |
| `RUMINATE` | `15` | Re-fold pinned roots. Prompts for target Hex ID (blank = global) and cycle count. |

### Analytics — Inspection & Persistence

| Command | # | Description |
|---|---|---|
| `METRICS` | `5`  | Live stats: atom/chunk population, meta RAM, blob cache occupancy, disk size, cache hit rate, tree depth. |
| `LOG`     | `6`  | Full identity-shift history. Every MORPH and PHOENIX operation recorded with timestamp. |
| `SAVE`    | `10` | Flush NodeMeta index to `vault.meta`. |
| `LOAD`    | `11` | Restore NodeMeta from `vault.meta`. Blobs are loaded lazily on first access. |

### Surgery — Structural Repair

| Command | # | Description |
|---|---|---|
| `PHOENIX` | `7`  | Redigestion protocol. Unrolls a node to raw text, re-ingests fresh, reroutes ancestors, purges old subtree. |
| `PIN`     | `8`  | Grant immortality to a node by Hex ID. Vitality set to 1.0. Exempt from all DREAM decay. |
| `RECOVER` | `9`  | Scan for independent root nodes (no parent dendrites). Prints IDs, vitalities, pin status. |
| `EXIT`    | `13` | Shut down. Save first if you want to persist state. |

---

## Workflow Examples

### Store and Retrieve

```
voltex_vault# INGEST
Enter data: the quick brown fox
[INFO] Synthesis Complete.
Root ID: a3f8c2e1d4b79f3c...

voltex_vault# UNROLL
Target Hex: a3f8c2e1d4b79f3c...
the quick brown fox
```

### Pin Critical Data

```
voltex_vault# INGEST
Enter data: critical configuration v2.1
Root ID: 84f02169afae8cc2...

voltex_vault# PIN
84f02169afae8cc2...
[PIN] Node [84f02169...] is IMMORTAL.

voltex_vault# DREAM    ← run as many times as needed
voltex_vault# UNROLL   ← pinned node still resolves
Target Hex: 84f02169afae8cc2...
critical configuration v2.1
```

### Bulk Ingestion + Metrics

```
voltex_vault# EVO
--- VOLTEX SYNTHESIS (1000 RECORDS) ---
[1000/1000] Metas:87185 Hot-blobs:538

voltex_vault# METRICS
 Population:      [538] Atoms | [86647] Chunks
 Meta RAM:        0.01 MB (always resident)
 Blob Cache RAM:  0.00 MB (538/4096 hot blobs)
 Blob File Size:  892416 bytes on disk
 Cache Hit Rate:  99.1%
```

> 538 unique atoms encode 87,185 nodes across 1000 JSON records — the shared field names, hex fragments, and value patterns collapse to the same leaf nodes across every record.

### Persist and Restore

```
voltex_vault# SAVE
[SAVE] Meta persisted (87185 nodes). Blob file: 892416 bytes.

  --- restart voltex ---

voltex_vault# LOAD
[LOAD] 87185 metas loaded. Blob window reset (lazy).

voltex_vault# UNROLL
Target Hex: <any previously ingested Root ID>
<original string>
```

---

## Export Utility

The export utility converts `vault.meta` + `vault.blob` into a compact portable snapshot (`vault.vtxe`) by replacing every 32-byte SHA-256 reference with a 4-byte row index.

### Why It Saves Space

```
Live vault references:  node with 2 children + 2 dendrites
  4 references × 32 bytes = 128 bytes of identity overhead

Exported references:
  4 references × 4 bytes  =  16 bytes of identity overhead

Result: ~8× reduction on reference data alone
```

### .vtxe File Format

```
┌─ HEADER  (24 bytes) ──────────────────────────────────────┐
│  magic: 0x56545845 ("VTXE")  version: 1                   │
│  node_count  atom_count  str_pool_sz  dend_pool_sz         │
└────────────────────────────────────────────────────────────┘
┌─ SECTION 1: ID INDEX TABLE  (N × 32 bytes) ───────────────┐
│  One SHA-256 hash per row. The ONLY place hashes appear.   │
│  Every cross-reference elsewhere is a row number (uint32). │
└────────────────────────────────────────────────────────────┘
┌─ SECTION 2: NODE TABLE  (N × 28 bytes) ───────────────────┐
│  child_a(u32)  child_b(u32)  str_off(u32)  str_len(u16)   │
│  dend_off(u32)  dend_cnt(u16)  vitality(f32)  type  pinned │
└────────────────────────────────────────────────────────────┘
┌─ SECTION 3: STRING POOL  (str_pool_sz bytes) ─────────────┐
│  Flat buffer. ATOM lexemes packed contiguously.            │
│  No null terminators — length stored in Node Table.        │
└────────────────────────────────────────────────────────────┘
┌─ SECTION 4: DENDRITE POOL  (dend_pool_sz × 4 bytes) ──────┐
│  Flat uint32_t array. Each node's parent list is a slice   │
│  indexed by [dend_off .. dend_off + dend_cnt).             │
└────────────────────────────────────────────────────────────┘
```

### Real-World Numbers (87k nodes)

```
  Header          :        24 bytes
  ID Index Table  : 2,789,920 bytes  (87,185 × 32)
  Node Table      : 2,441,180 bytes  (87,185 × 28)
  String Pool     :     1,118 bytes
  Dendrite Pool   :   693,176 bytes  (173,294 × 4)
  ─────────────────────────────────────────────────
  Export total    : 5,925,418 bytes
  Original est.   : 15,330,614 bytes
  Space saved     : 61.3%
```

### Export Commands

```bash
# Convert vault to compact export
./vtx_export export vault.meta vault.blob vault.vtxe

# Validate structural integrity of export
./vtx_export verify vault.vtxe

# Print file statistics
./vtx_export info vault.vtxe

# Rebuild vault files from export (round-trip)
./vtx_export import vault.vtxe restored.meta restored.blob
```

### Complete Export Workflow

```bash
# 1. Run voltex, ingest data, save
./voltex
  voltex_vault# EVO
  voltex_vault# SAVE
  voltex_vault# EXIT

# 2. Export
./vtx_export export vault.meta vault.blob vault.vtxe

# 3. Verify
./vtx_export verify vault.vtxe
# [VERIFY PASSED]

# 4. Ship / archive vault.vtxe

# 5. On destination machine — import and load
./vtx_export import vault.vtxe vault.meta vault.blob
./voltex
  voltex_vault# LOAD
  voltex_vault# UNROLL
  Target Hex: <original Root ID>
  <string reconstructed>
```

---

## File Reference

| File | Description |
|---|---|
| `vault.meta` | NodeMeta index. Written by `SAVE`, read by `LOAD`. Contains all graph structure, vitalities, pin flags, and blob offsets. Required for navigation. |
| `vault.blob` | Append-only binary blob log. Written continuously during ingestion — no explicit save needed. Contains raw lexeme text for ATOM nodes. |
| `vault.vtxe` | Compact export snapshot. Self-contained. Can be transmitted, archived, or imported into any Voltex instance. |
| `restored.meta` | Default output of `vtx_export import`. Drop-in replacement for `vault.meta`. |
| `restored.blob` | Default output of `vtx_export import`. Drop-in replacement for `vault.blob`. |

---

## Configuration

Key constants in `voltex_paged.cpp`:

| Constant | Default | Effect |
|---|---|---|
| `MAX_HOT_BLOBS` | `4096` | Max blobs in LRU cache. Raise for UNROLL/AUDIT-heavy workloads. |
| `DECAY_MULTIPLIER` | `0.95` | Vitality multiplied each DREAM cycle. Lower = faster forgetting. |
| `DECAY_THRESHOLD` | `0.2` | Vitality floor below which nodes are purged. |
| `MAX_BUF` | `1024` | Max reconstructed string length. Raise for long document ingestion. |
| `ATOM_LEAF_SIZE` | `4` | Max chars per leaf ATOM. Smaller = finer deduplication granularity. |

---

## Use Cases

**Deduplication-aware text storage** — Corpora with shared substrings (config files, log lines, API responses from the same schema) automatically share ATOM subtrees. Storage cost grows with unique content only.

**Content fingerprinting** — Every string has a deterministic Root ID. Re-ingest the content and compare IDs to verify integrity. Any modification to any character propagates a new hash to the root.

**Decaying memory with selective retention** — Model data with a natural time-to-live. Infrequently-accessed nodes decay and expire. Pin nodes that must survive indefinitely.

**Structural pattern analysis** — After bulk ingestion, the chunk-to-atom ratio reveals how much structural redundancy exists in the source data. Useful for schema analysis and compression estimation.

**Portable vault snapshots** — The `.vtxe` format is a self-contained, verifiable binary snapshot. Ship it, archive it, or load it into a fresh instance on a different machine with no shared state.

---

## Architecture Notes

The closest research analogues to Voltex are **Hyperdimensional Computing** (HDC), **Neural Turing Machines**, and episodic memory architectures — but it runs without weights, training, or inference infrastructure. Vitality is the weight. The graph is the model. DREAM is the training loop.

What makes the combination unusual:

- Storage structure and retrieval mechanism are the same graph — there is no separate index
- Forgetting is a first-class operation, not a side effect of eviction
- Structurally identical content is the same node regardless of how or when it was ingested
- The export format is to Voltex what ONNX is to a neural network — a portable, verifiable snapshot of learned structure

---

## License

MIT — see [LICENSE](LICENSE)
