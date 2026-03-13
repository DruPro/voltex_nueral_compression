// ═══════════════════════════════════════════════════════════════════
//  vtx_export.cpp  —  Voltex Schema-Aware Export Utility
//
//  Reads  : vault.meta  +  vault.blob  (Voltex paged format)
//  Writes : vault.vtxe  (compact indexed export)
//
//  What this does
//  ──────────────
//  The live vault represents every node by a 32-byte SHA-256 HexID.
//  Every child pointer, every dendrite, every cross-reference burns
//  32 bytes per link.  For a 100k-node vault that is:
//
//    child_a   : 100k × 32 =  3.2 MB
//    child_b   : 100k × 32 =  3.2 MB
//    dendrites : varies    = ~6–20 MB
//    blob ids  : 100k × 32 =  3.2 MB
//    ─────────────────────────────────
//    just IDs  :           ≈ 15–30 MB  overhead
//
//  The export collapses every HexID reference into a uint32_t
//  row index (4 bytes).  The hash is stored ONCE in a header
//  index table and never repeated.  All cross-references become
//  relative row numbers.
//
//  Export file layout  (vault.vtxe)
//  ─────────────────────────────────
//
//  ┌─ FILE HEADER ──────────────────────────────────────────────┐
//  │  magic      : uint32_t  = 0x56545845  ("VTXE")            │
//  │  version    : uint16_t  = 1                                │
//  │  node_count : uint32_t                                     │
//  │  atom_count : uint32_t                                     │
//  │  str_pool_sz: uint32_t  (bytes in string pool)             │
//  │  dend_pool_sz: uint32_t (total dendrite entries)           │
//  └────────────────────────────────────────────────────────────┘
//
//  ┌─ SECTION 1 : ID INDEX TABLE  (node_count × 32 bytes) ─────┐
//  │  Row i : HexID.hash[32]                                    │
//  │  Purpose: one lookup converts row→identity for verify      │
//  │  Indexed by row number — the ONLY place hashes live        │
//  └────────────────────────────────────────────────────────────┘
//
//  ┌─ SECTION 2 : NODE TABLE  (node_count × NodeRecord) ───────┐
//  │  Per record (fixed-width, 24 bytes):                       │
//  │    child_a  : uint32_t  (row index, UINT32_MAX = null)     │
//  │    child_b  : uint32_t  (row index, UINT32_MAX = null)     │
//  │    str_off  : uint32_t  (byte offset into string pool)     │
//  │    str_len  : uint16_t  (lexeme length, 0 for CHUNKs)      │
//  │    dend_off : uint32_t  (offset into dendrite pool)        │
//  │    dend_cnt : uint16_t  (number of dendrite entries)       │
//  │    vitality : float     (4 bytes)                          │
//  │    type     : uint8_t   (0=ATOM, 1=CHUNK)                  │
//  │    is_pinned: uint8_t                                       │
//  └────────────────────────────────────────────────────────────┘
//
//  ┌─ SECTION 3 : STRING POOL  (str_pool_sz bytes) ────────────┐
//  │  Flat byte buffer.  ATOMs index into here by str_off.      │
//  │  No null terminators — length is in NodeRecord.str_len.    │
//  │  CHUNKs have str_off=0, str_len=0.                         │
//  └────────────────────────────────────────────────────────────┘
//
//  ┌─ SECTION 4 : DENDRITE POOL  (dend_pool_sz × uint32_t) ────┐
//  │  Flat array of row indices.  Each node's dendrite list     │
//  │  is a contiguous slice [dend_off .. dend_off+dend_cnt).    │
//  └────────────────────────────────────────────────────────────┘
//
//  Storage comparison (100k nodes, avg lexeme 4 bytes)
//  ──────────────────────────────────────────────────
//  vault.meta (live)  : ~12 MB  (IDs everywhere)
//  vault.blob (live)  : ~800 KB (raw lexemes + ids)
//  vault.vtxe (export): ~3.2 MB  (IDs once + 24-byte records)
//
// ═══════════════════════════════════════════════════════════════════

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <ctime>

// ─────────────────────────────────────────────
// Constants mirrored from voltex_paged.cpp
// ─────────────────────────────────────────────
static constexpr int    SHA256_BLOCK_SIZE  = 32;
static constexpr int    MAX_HOT_BLOBS      = 4096;  // unused here but kept for clarity
static constexpr const char* META_FILE     = "vault.meta";
static constexpr const char* BLOB_FILE     = "vault.blob";
static constexpr const char* EXPORT_FILE   = "vault.vtxe";
static constexpr uint32_t    VTXE_MAGIC    = 0x56545845; // "VTXE"
static constexpr uint16_t    VTXE_VERSION  = 1;
static constexpr uint32_t    NULL_ROW      = UINT32_MAX;


// ─────────────────────────────────────────────
// HexID (self-contained copy)
// ─────────────────────────────────────────────
struct HexID {
    uint8_t hash[SHA256_BLOCK_SIZE] = {};

    bool operator==(const HexID& o) const {
        return std::memcmp(hash, o.hash, SHA256_BLOCK_SIZE) == 0;
    }
    bool isNull() const {
        for (int i = 0; i < SHA256_BLOCK_SIZE; ++i) if (hash[i]) return false;
        return true;
    }
    std::string toHexStr() const {
        char buf[65];
        for (int i = 0; i < 32; ++i) std::sprintf(buf + i * 2, "%02x", hash[i]);
        buf[64] = '\0';
        return {buf};
    }
};

struct HexIDHasher {
    std::size_t operator()(const HexID& id) const {
        uint32_t v; std::memcpy(&v, id.hash, 4); return v;
    }
};

// ─────────────────────────────────────────────
// On-disk structures from voltex_paged.cpp
// (reproduced here so the exporter is standalone)
// ─────────────────────────────────────────────
enum class NodeType : uint8_t { ATOM = 0, CHUNK = 1 };

// What we read back from vault.meta
struct RawMeta {
    HexID    id;
    HexID    child_a_id;
    HexID    child_b_id;
    uint64_t blob_offset;
    float    vitality;
    NodeType type;
    bool     is_pinned;
    std::vector<HexID> dendrites;
};

// What we read back from vault.blob at a given offset
struct RawBlob {
    HexID       id;
    std::string lexeme;
};

// ─────────────────────────────────────────────
// Export record — fixed 24 bytes on disk
// ─────────────────────────────────────────────
#pragma pack(push, 1)
struct NodeRecord {
    uint32_t child_a;   //  4  row index or NULL_ROW
    uint32_t child_b;   //  4
    uint32_t str_off;   //  4  byte offset into string pool
    uint16_t str_len;   //  2  0 for CHUNKs
    uint32_t dend_off;  //  4  offset into dendrite pool (uint32_t entries)
    uint16_t dend_cnt;  //  2
    float    vitality;  //  4
    uint8_t  type;      //  1
    uint8_t  is_pinned; //  1
                        // 26 bytes — pad to 28 for alignment
    uint8_t  _pad[2];
};                      // = 28 bytes per record
#pragma pack(pop)

// Export file header — fixed 24 bytes
#pragma pack(push, 1)
struct ExportHeader {
    uint32_t magic;         //  4
    uint16_t version;       //  2
    uint16_t _pad;          //  2
    uint32_t node_count;    //  4
    uint32_t atom_count;    //  4
    uint32_t str_pool_sz;   //  4
    uint32_t dend_pool_sz;  //  4
                            // 24 bytes total
};
#pragma pack(pop)

// ─────────────────────────────────────────────
// Reader: vault.meta
// ─────────────────────────────────────────────
std::vector<RawMeta> readMeta(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::fprintf(stderr, "[ERROR] Cannot open %s\n", path.c_str());
        return {};
    }

    int count = 0;
    f.read(reinterpret_cast<char*>(&count), sizeof(int));

    std::vector<RawMeta> nodes;
    nodes.reserve(count);

    for (int i = 0; i < count; ++i) {
        RawMeta m;
        f.read(reinterpret_cast<char*>(&m.id),          sizeof(HexID));
        f.read(reinterpret_cast<char*>(&m.child_a_id),  sizeof(HexID));
        f.read(reinterpret_cast<char*>(&m.child_b_id),  sizeof(HexID));
        f.read(reinterpret_cast<char*>(&m.blob_offset), sizeof(uint64_t));
        f.read(reinterpret_cast<char*>(&m.vitality),    sizeof(float));
        f.read(reinterpret_cast<char*>(&m.type),        sizeof(NodeType));
        int pin; f.read(reinterpret_cast<char*>(&pin),  sizeof(int));
        m.is_pinned = (pin != 0);

        int dc; f.read(reinterpret_cast<char*>(&dc), sizeof(int));
        m.dendrites.resize(dc);
        if (dc > 0)
            f.read(reinterpret_cast<char*>(m.dendrites.data()), dc * sizeof(HexID));

        nodes.push_back(std::move(m));
    }
    return nodes;
}

// ─────────────────────────────────────────────
// Reader: single blob from vault.blob at offset
// ─────────────────────────────────────────────
RawBlob readBlobAt(std::ifstream& bf, uint64_t offset) {
    bf.seekg(static_cast<std::streamoff>(offset));
    RawBlob blob;
    bf.read(reinterpret_cast<char*>(blob.id.hash), 32);
    uint32_t ll = 0;
    bf.read(reinterpret_cast<char*>(&ll), sizeof(uint32_t));
    if (ll > 0) {
        blob.lexeme.resize(ll);
        bf.read(blob.lexeme.data(), ll);
    }
    return blob;
}

// ─────────────────────────────────────────────
// Export  core
// ─────────────────────────────────────────────
bool exportVault(const std::string& meta_path,
                 const std::string& blob_path,
                 const std::string& out_path)
{
    std::printf("\n["  "EXPORT"  "] Reading meta index from %s ...\n",
        meta_path.c_str());

    // ── Phase 1: Load all meta ──
    std::vector<RawMeta> nodes = readMeta(meta_path);
    if (nodes.empty()) {
        std::puts("[ERROR] No nodes found in meta file.");
        return false;
    }

    std::printf("["  "EXPORT"  "] Loaded %zu meta records.\n", nodes.size());

    // ── Phase 2: Build HexID → row index ──
    // This is the core substitution: every 32-byte HexID becomes a 4-byte uint32_t
    std::unordered_map<HexID, uint32_t, HexIDHasher> id_to_row;
    id_to_row.reserve(nodes.size());
    for (uint32_t i = 0; i < static_cast<uint32_t>(nodes.size()); ++i)
        id_to_row[nodes[i].id] = i;

    // ── Phase 3: Open blob file for lexeme reads ──
    std::ifstream blob_f(blob_path, std::ios::binary);
    if (!blob_f) {
        std::fprintf(stderr, "[WARN] Blob file %s not found. ATOMs will have empty lexemes.\n",
            blob_path.c_str());
    }

    // ── Phase 4: Build string pool + dendrite pool ──
    // String pool: flat byte buffer, ATOMs point into it by offset
    // Dendrite pool: flat uint32_t array, each node has a contiguous slice
    std::string    str_pool;
    std::vector<uint32_t> dend_pool;

    str_pool.reserve(nodes.size() * 4);    // rough pre-alloc
    dend_pool.reserve(nodes.size() * 2);

    std::vector<NodeRecord> records(nodes.size());

    int atoms = 0, chunks = 0, blobs_read = 0;

    for (uint32_t i = 0; i < static_cast<uint32_t>(nodes.size()); ++i) {
        const RawMeta& m = nodes[i];
        NodeRecord&    r = records[i];

        // ── child pointers → row indices ──
        r.child_a = m.child_a_id.isNull() ? NULL_ROW
                    : (id_to_row.count(m.child_a_id) ? id_to_row[m.child_a_id] : NULL_ROW);
        r.child_b = m.child_b_id.isNull() ? NULL_ROW
                    : (id_to_row.count(m.child_b_id) ? id_to_row[m.child_b_id] : NULL_ROW);

        // ── vitality / type / pin ──
        r.vitality  = m.vitality;
        r.type      = static_cast<uint8_t>(m.type);
        r.is_pinned = m.is_pinned ? 1 : 0;
        r._pad[0]   = r._pad[1] = 0;

        // ── lexeme → string pool ──
        if (m.type == NodeType::ATOM && blob_f.is_open()) {
            RawBlob blob = readBlobAt(blob_f, m.blob_offset);
            ++blobs_read;

            r.str_off = static_cast<uint32_t>(str_pool.size());
            r.str_len = static_cast<uint16_t>(
                blob.lexeme.size() > 0xFFFF ? 0xFFFF : blob.lexeme.size());
            str_pool.append(blob.lexeme.data(), r.str_len);
            ++atoms;
        } else {
            // CHUNK or no blob file — no string data
            r.str_off = 0;
            r.str_len = 0;
            ++chunks;
        }

        // ── dendrites → dendrite pool ──
        r.dend_off = static_cast<uint32_t>(dend_pool.size());
        r.dend_cnt = 0;

        for (const HexID& d : m.dendrites) {
            auto it = id_to_row.find(d);
            if (it != id_to_row.end()) {
                dend_pool.push_back(it->second);
                ++r.dend_cnt;
            }
            // Silently drop dendrites that reference purged nodes
        }
    }

    // ── Phase 5: Write export file ──
    std::ofstream out(out_path, std::ios::binary);
    if (!out) {
        std::fprintf(stderr, "[ERROR] Cannot write to %s\n", out_path.c_str());
        return false;
    }

    // Header
    ExportHeader hdr;
    hdr.magic        = VTXE_MAGIC;
    hdr.version      = VTXE_VERSION;
    hdr._pad         = 0;
    hdr.node_count   = static_cast<uint32_t>(nodes.size());
    hdr.atom_count   = static_cast<uint32_t>(atoms);
    hdr.str_pool_sz  = static_cast<uint32_t>(str_pool.size());
    hdr.dend_pool_sz = static_cast<uint32_t>(dend_pool.size());
    out.write(reinterpret_cast<const char*>(&hdr), sizeof(ExportHeader));

    // Section 1: ID index table  (node_count × 32 bytes)
    for (const RawMeta& m : nodes)
        out.write(reinterpret_cast<const char*>(m.id.hash), SHA256_BLOCK_SIZE);

    // Section 2: Node table  (node_count × sizeof(NodeRecord))
    out.write(reinterpret_cast<const char*>(records.data()),
              records.size() * sizeof(NodeRecord));

    // Section 3: String pool
    if (!str_pool.empty())
        out.write(str_pool.data(), str_pool.size());

    // Section 4: Dendrite pool
    if (!dend_pool.empty())
        out.write(reinterpret_cast<const char*>(dend_pool.data()),
                  dend_pool.size() * sizeof(uint32_t));

    out.close();

    // ── Phase 6: Report ──
    uint64_t export_bytes = sizeof(ExportHeader)
        + static_cast<uint64_t>(nodes.size()) * SHA256_BLOCK_SIZE  // ID index
        + static_cast<uint64_t>(nodes.size()) * sizeof(NodeRecord) // node table
        + str_pool.size()                                           // string pool
        + dend_pool.size() * sizeof(uint32_t);                     // dendrite pool

    // Estimate original footprint for comparison
    // meta:  each node = 3×HexID(96) + 8 + 4 + 1 + 1 + 1 + 1 + 4 + (dendrites×32)
    uint64_t meta_bytes = 0;
    for (const RawMeta& m : nodes)
        meta_bytes += 96 + 8 + 4 + 4 + static_cast<uint64_t>(m.dendrites.size()) * 32;

    // blob: each atom = 32 (id) + 4 (len) + lexeme
    uint64_t blob_bytes = static_cast<uint64_t>(atoms) * 36 + str_pool.size();

    uint64_t original_bytes = meta_bytes + blob_bytes;
    float    ratio          = original_bytes > 0
                              ? 100.f * (1.f - static_cast<float>(export_bytes) /
                                              static_cast<float>(original_bytes))
                              : 0.f;

    std::printf("\n["  "EXPORT COMPLETE"  "]\n");
    std::printf("  Output file   : %s\n", out_path.c_str());
    std::printf("  Nodes         : %u  (%d atoms / %d chunks)\n",
        hdr.node_count, atoms, chunks);
    std::printf("  Blobs read    : %d\n", blobs_read);
    std::printf("\n  ── Size breakdown ──\n");
    std::printf("  Header        : %4zu bytes\n",      sizeof(ExportHeader));
    std::printf("  ID index      : %6llu bytes  (%u × 32)\n",
        static_cast<unsigned long long>(
            static_cast<uint64_t>(nodes.size()) * SHA256_BLOCK_SIZE),
        hdr.node_count);
    std::printf("  Node table    : %6llu bytes  (%u × %zu)\n",
        static_cast<unsigned long long>(
            static_cast<uint64_t>(nodes.size()) * sizeof(NodeRecord)),
        hdr.node_count, sizeof(NodeRecord));
    std::printf("  String pool   : %6u bytes\n",      hdr.str_pool_sz);
    std::printf("  Dendrite pool : %6llu bytes  (%u × 4)\n",
        static_cast<unsigned long long>(
            static_cast<uint64_t>(dend_pool.size()) * sizeof(uint32_t)),
        hdr.dend_pool_sz);
    std::printf("  ─────────────────────────────────\n");
    std::printf("  Export total  : "  "%llu bytes"  "\n",
        static_cast<unsigned long long>(export_bytes));
    std::printf("  Original est. : "  "%llu bytes"  "\n",
        static_cast<unsigned long long>(original_bytes));
    std::printf("  Space saved   : "  "%.1f%%\n" , ratio);

    return true;
}

// ─────────────────────────────────────────────
// Verify  (round-trip sanity check)
//   Reads the .vtxe file back and confirms:
//   1. Magic + version correct
//   2. Row count matches
//   3. A sample of row→ID lookups is consistent
//   4. child_a/child_b rows are in-bounds or NULL_ROW
//   5. dend_off + dend_cnt fits inside dendrite pool
//   6. str_off + str_len fits inside string pool
// ─────────────────────────────────────────────
bool verifyExport(const std::string& path) {
    std::printf("\n["  "VERIFY"  "] Checking %s ...\n", path.c_str());

    std::ifstream f(path, std::ios::binary);
    if (!f) { std::fprintf(stderr, "[ERROR] Cannot open %s\n", path.c_str()); return false; }

    // Read header
    ExportHeader hdr;
    f.read(reinterpret_cast<char*>(&hdr), sizeof(ExportHeader));

    if (hdr.magic != VTXE_MAGIC) {
        std::printf("["  "FAIL"  "] Bad magic: 0x%08X\n", hdr.magic);
        return false;
    }
    if (hdr.version != VTXE_VERSION) {
        std::printf("["  "FAIL"  "] Unknown version: %u\n", hdr.version);
        return false;
    }
    std::printf("  Header        : OK  (v%u, %u nodes)\n", hdr.version, hdr.node_count);

    // Read ID index
    std::vector<HexID> id_index(hdr.node_count);
    for (uint32_t i = 0; i < hdr.node_count; ++i)
        f.read(reinterpret_cast<char*>(id_index[i].hash), SHA256_BLOCK_SIZE);

    // Read node table
    std::vector<NodeRecord> records(hdr.node_count);
    f.read(reinterpret_cast<char*>(records.data()),
           hdr.node_count * sizeof(NodeRecord));

    // Read string pool
    std::string str_pool(hdr.str_pool_sz, '\0');
    if (hdr.str_pool_sz > 0)
        f.read(str_pool.data(), hdr.str_pool_sz);

    // Read dendrite pool
    std::vector<uint32_t> dend_pool(hdr.dend_pool_sz);
    if (hdr.dend_pool_sz > 0)
        f.read(reinterpret_cast<char*>(dend_pool.data()),
               hdr.dend_pool_sz * sizeof(uint32_t));

    // Validate every record
    int errors = 0;
    for (uint32_t i = 0; i < hdr.node_count; ++i) {
        const NodeRecord& r = records[i];

        // child bounds
        if (r.child_a != NULL_ROW && r.child_a >= hdr.node_count) {
            std::printf("  [ROW %u] child_a=%u out of bounds\n", i, r.child_a); ++errors;
        }
        if (r.child_b != NULL_ROW && r.child_b >= hdr.node_count) {
            std::printf("  [ROW %u] child_b=%u out of bounds\n", i, r.child_b); ++errors;
        }

        // string pool bounds
        if (r.str_len > 0) {
            uint32_t end = r.str_off + r.str_len;
            if (end > hdr.str_pool_sz) {
                std::printf("  [ROW %u] str_off+str_len=%u overruns pool (%u)\n",
                    i, end, hdr.str_pool_sz);
                ++errors;
            }
        }

        // dendrite pool bounds
        if (r.dend_cnt > 0) {
            uint32_t end = r.dend_off + r.dend_cnt;
            if (end > hdr.dend_pool_sz) {
                std::printf("  [ROW %u] dend_off+dend_cnt=%u overruns pool (%u)\n",
                    i, end, hdr.dend_pool_sz);
                ++errors;
            } else {
                // each dendrite row must be in-bounds
                for (uint16_t d = 0; d < r.dend_cnt; ++d) {
                    uint32_t dr = dend_pool[r.dend_off + d];
                    if (dr >= hdr.node_count) {
                        std::printf("  [ROW %u] dendrite[%u]=%u out of bounds\n", i, d, dr);
                        ++errors;
                    }
                }
            }
        }
    }

    if (errors == 0) {
        std::printf("  Node records  : OK  (all %u records valid)\n", hdr.node_count);
        std::printf("  String pool   : OK  (%u bytes)\n", hdr.str_pool_sz);
        std::printf("  Dendrite pool : OK  (%u entries)\n", hdr.dend_pool_sz);

        // Print a sample of decoded atoms
        std::printf("\n  ── Sample ATOMs ──\n");
        int shown = 0;
        for (uint32_t i = 0; i < hdr.node_count && shown < 8; ++i) {
            if (records[i].type == 0 && records[i].str_len > 0) {
                std::string lex(str_pool.data() + records[i].str_off, records[i].str_len);
                std::printf("  [row %4u] «%s»  vitality=%.2f  pinned=%d\n",
                    i, lex.c_str(), records[i].vitality, records[i].is_pinned);
                ++shown;
            }
        }

        std::printf("\n["  "VERIFY PASSED"  "]\n");
        return true;
    } else {
        std::printf("\n["  "VERIFY FAILED"  "] %d error(s) found.\n", errors);
        return false;
    }
}

// ─────────────────────────────────────────────
// Import  (vtxe → rebuild vault.meta + vault.blob)
//   Reverses the export: re-expands row indices
//   back to HexIDs using the ID index table and
//   rewrites fresh vault.meta + vault.blob files.
//   Useful for migrating a compact export back
//   into a running Voltex instance.
// ─────────────────────────────────────────────
bool importExport(const std::string& vtxe_path,
                  const std::string& out_meta_path,
                  const std::string& out_blob_path)
{
    std::printf("\n["  "IMPORT"  "] Rebuilding vault from %s ...\n",
        vtxe_path.c_str());

    std::ifstream f(vtxe_path, std::ios::binary);
    if (!f) { std::fprintf(stderr, "[ERROR] Cannot open %s\n", vtxe_path.c_str()); return false; }

    ExportHeader hdr;
    f.read(reinterpret_cast<char*>(&hdr), sizeof(ExportHeader));
    if (hdr.magic != VTXE_MAGIC) {
        std::puts("[ERROR] Not a valid .vtxe file."); return false;
    }

    std::vector<HexID> id_index(hdr.node_count);
    for (uint32_t i = 0; i < hdr.node_count; ++i)
        f.read(reinterpret_cast<char*>(id_index[i].hash), SHA256_BLOCK_SIZE);

    std::vector<NodeRecord> records(hdr.node_count);
    f.read(reinterpret_cast<char*>(records.data()),
           hdr.node_count * sizeof(NodeRecord));

    std::string str_pool(hdr.str_pool_sz, '\0');
    if (hdr.str_pool_sz > 0) f.read(str_pool.data(), hdr.str_pool_sz);

    std::vector<uint32_t> dend_pool(hdr.dend_pool_sz);
    if (hdr.dend_pool_sz > 0)
        f.read(reinterpret_cast<char*>(dend_pool.data()),
               hdr.dend_pool_sz * sizeof(uint32_t));

    f.close();

    // ── Rebuild blob file ──
    std::ofstream blob_out(out_blob_path, std::ios::binary);
    if (!blob_out) { std::fprintf(stderr, "[ERROR] Cannot write %s\n", out_blob_path.c_str()); return false; }

    // blob offsets indexed by row
    std::vector<uint64_t> blob_offsets(hdr.node_count, 0);
    uint64_t blob_pos = 0;

    for (uint32_t i = 0; i < hdr.node_count; ++i) {
        const NodeRecord& r = records[i];
        blob_offsets[i] = blob_pos;

        // Write: id (32) + len (4) + lexeme
        blob_out.write(reinterpret_cast<const char*>(id_index[i].hash), SHA256_BLOCK_SIZE);
        uint32_t ll = r.str_len;
        blob_out.write(reinterpret_cast<const char*>(&ll), sizeof(uint32_t));
        if (ll > 0)
            blob_out.write(str_pool.data() + r.str_off, ll);

        blob_pos += SHA256_BLOCK_SIZE + sizeof(uint32_t) + ll;
    }
    uint64_t blob_eof = blob_pos;
    blob_out.close();

    // ── Rebuild meta file ──
    std::ofstream meta_out(out_meta_path, std::ios::binary);
    if (!meta_out) { std::fprintf(stderr, "[ERROR] Cannot write %s\n", out_meta_path.c_str()); return false; }

    int count = static_cast<int>(hdr.node_count);
    meta_out.write(reinterpret_cast<const char*>(&count), sizeof(int));

    for (uint32_t i = 0; i < hdr.node_count; ++i) {
        const NodeRecord& r = records[i];

        // id
        meta_out.write(reinterpret_cast<const char*>(id_index[i].hash), sizeof(HexID));

        // child_a_id
        HexID null_id{};
        const HexID& ca = (r.child_a != NULL_ROW) ? id_index[r.child_a] : null_id;
        const HexID& cb = (r.child_b != NULL_ROW) ? id_index[r.child_b] : null_id;
        meta_out.write(reinterpret_cast<const char*>(&ca), sizeof(HexID));
        meta_out.write(reinterpret_cast<const char*>(&cb), sizeof(HexID));

        // blob_offset
        meta_out.write(reinterpret_cast<const char*>(&blob_offsets[i]), sizeof(uint64_t));

        // vitality
        meta_out.write(reinterpret_cast<const char*>(&r.vitality), sizeof(float));

        // type
        meta_out.write(reinterpret_cast<const char*>(&r.type), sizeof(uint8_t));

        // is_pinned (as int)
        int pin = r.is_pinned ? 1 : 0;
        meta_out.write(reinterpret_cast<const char*>(&pin), sizeof(int));

        // dendrites (re-expand row indices → HexIDs)
        int dc = static_cast<int>(r.dend_cnt);
        meta_out.write(reinterpret_cast<const char*>(&dc), sizeof(int));
        for (uint16_t d = 0; d < r.dend_cnt; ++d) {
            uint32_t dr = dend_pool[r.dend_off + d];
            const HexID& dh = (dr < hdr.node_count) ? id_index[dr] : null_id;
            meta_out.write(reinterpret_cast<const char*>(&dh), sizeof(HexID));
        }
    }

    // blob_eof sentinel
    meta_out.write(reinterpret_cast<const char*>(&blob_eof), sizeof(uint64_t));
    meta_out.close();

    std::printf("["  "IMPORT COMPLETE"  "] "
                "%u nodes → %s + %s\n",
                hdr.node_count,
                out_meta_path.c_str(),
                out_blob_path.c_str());
    return true;
}

// ─────────────────────────────────────────────
// Print .vtxe file info without full verify
// ─────────────────────────────────────────────
void printExportInfo(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::fprintf(stderr, "[ERROR] Cannot open %s\n", path.c_str()); return; }

    ExportHeader hdr;
    f.read(reinterpret_cast<char*>(&hdr), sizeof(ExportHeader));

    uint64_t total_sz = sizeof(ExportHeader)
        + static_cast<uint64_t>(hdr.node_count) * SHA256_BLOCK_SIZE
        + static_cast<uint64_t>(hdr.node_count) * sizeof(NodeRecord)
        + hdr.str_pool_sz
        + static_cast<uint64_t>(hdr.dend_pool_sz) * sizeof(uint32_t);

    std::printf("\n["  "VTXE INFO"  "] %s\n", path.c_str());
    std::printf("  Magic         : 0x%08X (%s)\n", hdr.magic,
        hdr.magic == VTXE_MAGIC ?  "OK"  :  "BAD" );
    std::printf("  Version       : %u\n",     hdr.version);
    std::printf("  Nodes         : %u\n",     hdr.node_count);
    std::printf("  Atoms         : %u\n",     hdr.atom_count);
    std::printf("  String pool   : %u bytes\n", hdr.str_pool_sz);
    std::printf("  Dendrite pool : %u entries\n", hdr.dend_pool_sz);
    std::printf("  NodeRecord    : %zu bytes each\n", sizeof(NodeRecord));
    std::printf("  File size est : "  "%llu bytes"  "\n",
        static_cast<unsigned long long>(total_sz));
}

// ─────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────
void printUsage(const char* prog) {
    std::printf("\nUsage:\n");
    std::printf("  %s export  [meta] [blob] [out.vtxe]   — Convert vault to compact export\n", prog);
    std::printf("  %s verify  [file.vtxe]                — Validate export integrity\n", prog);
    std::printf("  %s import  [file.vtxe] [out_meta] [out_blob]  — Rebuild vault files\n", prog);
    std::printf("  %s info    [file.vtxe]                — Print export file stats\n", prog);
    std::printf("\nDefaults (when paths omitted):\n");
    std::printf("  meta  = vault.meta\n");
    std::printf("  blob  = vault.blob\n");
    std::printf("  vtxe  = vault.vtxe\n\n");
}

int main(int argc, char* argv[]) {
    std::printf("\n\033[1;35m vtx_export \033[1;30m──╼ \033[0;37mVoltex Schema-Aware Export Utility\033[0m\n");
    std::printf("\033[1;30m ─────────────────────────────────────────\033[0m\n");

    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "export") {
        std::string meta = (argc > 2) ? argv[2] : META_FILE;
        std::string blob = (argc > 3) ? argv[3] : BLOB_FILE;
        std::string out  = (argc > 4) ? argv[4] : EXPORT_FILE;
        return exportVault(meta, blob, out) ? 0 : 1;

    } else if (cmd == "verify") {
        std::string vtxe = (argc > 2) ? argv[2] : EXPORT_FILE;
        return verifyExport(vtxe) ? 0 : 1;

    } else if (cmd == "import") {
        std::string vtxe     = (argc > 2) ? argv[2] : EXPORT_FILE;
        std::string out_meta = (argc > 3) ? argv[3] : "restored.meta";
        std::string out_blob = (argc > 4) ? argv[4] : "restored.blob";
        return importExport(vtxe, out_meta, out_blob) ? 0 : 1;

    } else if (cmd == "info") {
        std::string vtxe = (argc > 2) ? argv[2] : EXPORT_FILE;
        printExportInfo(vtxe);
        return 0;

    } else {
        std::fprintf(stderr, "[ERROR] Unknown command: %s\n", cmd.c_str());
        printUsage(argv[0]);
        return 1;
    }
}
