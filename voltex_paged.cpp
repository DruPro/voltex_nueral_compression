#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <list>
#include <unordered_map>
#include <algorithm>
#include <memory>
#include <cstring>
#include <cmath>
#include <ctime>
#include <cstdlib>
#include <functional>
#include <cassert>
#include <openssl/sha.h>
#include <windows.h>
#include <algorithm> // for std::max

// ─────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────
static constexpr int   SHA256_BLOCK_SIZE = 32;
static constexpr float DECAY_MULTIPLIER  = 0.95f;
static constexpr float DECAY_THRESHOLD   = 0.2f;
static constexpr int   MAX_BUF           = 1024;

// Pager tuning — only this many blobs live in RAM at once
static constexpr int   MAX_HOT_BLOBS     = 4096;

static constexpr const char* META_FILE   = "vault.meta";   // always-resident index
static constexpr const char* BLOB_FILE   = "vault.blob";   // fat data, seeked on demand


// ─────────────────────────────────────────────
// HexID
// ─────────────────────────────────────────────
struct HexID {
    uint8_t hash[SHA256_BLOCK_SIZE] = {};

    bool operator==(const HexID& o) const {
        return std::memcmp(hash, o.hash, SHA256_BLOCK_SIZE) == 0;
    }
    bool operator!=(const HexID& o) const { return !(*this == o); }

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
        uint32_t val; std::memcpy(&val, id.hash, 4); return val;
    }
};

// ─────────────────────────────────────────────
// SHA helpers
// ─────────────────────────────────────────────
HexID computeSHA(const void* data, std::size_t len) {
    HexID out;
    SHA256(reinterpret_cast<const unsigned char*>(data), len, out.hash);
    return out;
}
HexID computeSHADual(const HexID& a, const HexID& b) {
    uint8_t raw[64];
    std::memcpy(raw,      a.hash, 32);
    std::memcpy(raw + 32, b.hash, 32);
    return computeSHA(raw, 64);
}
HexID hexIDFromStr(const std::string& s) { return computeSHA(s.data(), s.size()); }

// ─────────────────────────────────────────────
// NodeType
// ─────────────────────────────────────────────
enum class NodeType : uint8_t { ATOM = 0, CHUNK = 1 };

// ─────────────────────────────────────────────
// NodeMeta  — always in RAM (~120 bytes)
//   Contains everything needed for dream-cycle,
//   graph traversal, and vitality decisions
//   WITHOUT touching the blob file.
// ─────────────────────────────────────────────
struct NodeMeta {
    HexID    id;                    // 32 bytes  identity
    HexID    child_a_id;            // 32 bytes  child reference (null if ATOM)
    HexID    child_b_id;            // 32 bytes  child reference (null if ATOM)
    uint64_t blob_offset = 0;       //  8 bytes  where NodeBlob lives on disk
    float    vitality    = 1.0f;    //  4 bytes
    NodeType type        = NodeType::ATOM; // 1 byte
    bool     is_pinned   = false;   //  1 byte
    bool     blob_dirty  = false;   //  1 byte  blob needs re-write
    uint8_t  _pad        = 0;       //  1 byte  alignment

    std::vector<HexID> dendrites;   // parent IDs  (heap, but small)
    NodeMeta* next      = nullptr;  // intrusive list
};                                  // ~120 bytes + dendrite heap

// ─────────────────────────────────────────────
// NodeBlob  — lives on disk, loaded on demand
//   Only needed for AUDIT, UNROLL, HUNT output
// ─────────────────────────────────────────────
struct NodeBlob {
    HexID       id;
    std::string lexeme;             // only populated for ATOMs
};

// ─────────────────────────────────────────────
// History
// ─────────────────────────────────────────────
struct History {
    HexID    old_id, new_id;
    char     timestamp[20] = {};
    History* next = nullptr;
};

// ─────────────────────────────────────────────
// ──  V A U L T   P A G E R  ──
//
//  meta_map   : HexID → NodeMeta*   (always resident)
//  blob_cache : HexID → NodeBlob    (hot window, LRU evicted)
//  blob_file  : seekable binary     (cold storage)
//
// ─────────────────────────────────────────────
class VaultPager {
public:
    // ── intrusive list head (owns all NodeMeta*) ──
    NodeMeta* vault = nullptr;

    // ── O(1) meta lookup ──
    std::unordered_map<HexID, NodeMeta*, HexIDHasher> meta_map;

    // ── blob cache + LRU order ──
    std::unordered_map<HexID, NodeBlob, HexIDHasher> blob_cache;
    std::list<HexID>                                  lru_order;

    // ── disk handle ──
    std::fstream blob_fstream;
    uint64_t     blob_eof = 0;   // append position

    // ── stats ──
    uint64_t cache_hits   = 0;
    uint64_t cache_misses = 0;

    // ────────────────────────────────────────
    // Lifecycle
    // ────────────────────────────────────────
    VaultPager() {
        // Open blob file for read+write, create if absent
        blob_fstream.open(BLOB_FILE, std::ios::in | std::ios::out | std::ios::binary);
        if (!blob_fstream.is_open()) {
            // Create fresh
            std::ofstream tmp(BLOB_FILE, std::ios::binary); tmp.close();
            blob_fstream.open(BLOB_FILE, std::ios::in | std::ios::out | std::ios::binary);
        }
        // Measure existing size
        blob_fstream.seekg(0, std::ios::end);
        blob_eof = static_cast<uint64_t>(blob_fstream.tellg());
    }

    ~VaultPager() {
        if (blob_fstream.is_open()) blob_fstream.close();
        NodeMeta* c = vault;
        while (c) { NodeMeta* nx = c->next; delete c; c = nx; }
    }

    // ────────────────────────────────────────
    // Meta access
    // ────────────────────────────────────────
    void mapMeta(NodeMeta* m) {
        if (m) meta_map[m->id] = m;
    }

    void unmapMeta(const HexID& id) {
        meta_map.erase(id);
        blob_cache.erase(id);
        // Remove from LRU
        lru_order.remove(id);
    }

    NodeMeta* findMeta(const HexID& id) {
        auto it = meta_map.find(id);
        return it != meta_map.end() ? it->second : nullptr;
    }

    NodeMeta* findMetaFromHexStr(const std::string& hex) {
        if (hex.size() != 64) return nullptr;
        HexID tmp;
        for (int i = 0; i < 32; ++i) {
            unsigned int byte;
            if (std::sscanf(hex.c_str() + i * 2, "%02x", &byte) != 1) return nullptr;
            tmp.hash[i] = static_cast<uint8_t>(byte);
        }
        return findMeta(tmp);
    }

    // ────────────────────────────────────────
    // Blob I/O
    // ────────────────────────────────────────

    // Serialize a blob to the blob file, return its offset
    uint64_t writeBlob(const NodeBlob& blob) {
        uint64_t offset = blob_eof;
        blob_fstream.seekp(static_cast<std::streamoff>(offset));

        // id (32 bytes)
        blob_fstream.write(reinterpret_cast<const char*>(blob.id.hash), 32);

        // lexeme length + data
        uint32_t ll = static_cast<uint32_t>(blob.lexeme.size());
        blob_fstream.write(reinterpret_cast<const char*>(&ll), sizeof(uint32_t));
        if (ll > 0) blob_fstream.write(blob.lexeme.data(), ll);

        blob_fstream.flush();
        blob_eof = offset + 32 + sizeof(uint32_t) + ll;
        return offset;
    }

    // Overwrite an existing blob in-place (only safe if same size or smaller)
    // For simplicity we always append and update the meta offset
    uint64_t rewriteBlob(const NodeBlob& blob) {
        return writeBlob(blob);  // append strategy: old offset becomes orphaned
    }

    NodeBlob deserializeBlob(uint64_t offset) {
        blob_fstream.seekg(static_cast<std::streamoff>(offset));
        NodeBlob blob;

        blob_fstream.read(reinterpret_cast<char*>(blob.id.hash), 32);

        uint32_t ll = 0;
        blob_fstream.read(reinterpret_cast<char*>(&ll), sizeof(uint32_t));
        if (ll > 0) {
            blob.lexeme.resize(ll);
            blob_fstream.read(blob.lexeme.data(), ll);
        }
        return blob;
    }

    // ────────────────────────────────────────
    // LRU blob cache
    // ────────────────────────────────────────
    void touchLRU(const HexID& id) {
        lru_order.remove(id);
        lru_order.push_back(id);
    }

    void evictCold() {
        // Walk from front (oldest) and evict first unpinned blob
        for (auto it = lru_order.begin(); it != lru_order.end(); ++it) {
            NodeMeta* m = findMeta(*it);
            if (!m || !m->is_pinned) {
                blob_cache.erase(*it);
                lru_order.erase(it);
                return;
            }
        }
        // All pinned — force evict oldest anyway
        if (!lru_order.empty()) {
            blob_cache.erase(lru_order.front());
            lru_order.pop_front();
        }
    }

    // Primary accessor — loads from disk on miss
    const NodeBlob* getBlob(const HexID& id) {
        // Cache hit
        auto it = blob_cache.find(id);
        if (it != blob_cache.end()) {
            ++cache_hits;
            touchLRU(id);
            return &it->second;
        }

        // Cache miss — load from disk
        ++cache_misses;
        NodeMeta* meta = findMeta(id);
        if (!meta) return nullptr;

        if (blob_cache.size() >= MAX_HOT_BLOBS) evictCold();

        NodeBlob blob = deserializeBlob(meta->blob_offset);
        blob_cache[id] = std::move(blob);
        lru_order.push_back(id);
        return &blob_cache[id];
    }

    // Force a blob into cache (used during ingest)
    void cacheBlob(NodeBlob blob) {
        if (blob_cache.size() >= MAX_HOT_BLOBS) evictCold();
        HexID id = blob.id;
        blob_cache[id] = std::move(blob);
        touchLRU(id);
    }

    // ────────────────────────────────────────
    // Count helpers
    // ────────────────────────────────────────
    int countAtoms() const {
        int c = 0;
        for (NodeMeta* n = vault; n; n = n->next)
            if (n->type == NodeType::ATOM) ++c;
        return c;
    }
    int countChunks() const {
        int c = 0;
        for (NodeMeta* n = vault; n; n = n->next)
            if (n->type == NodeType::CHUNK) ++c;
        return c;
    }
    int countTotal() const {
        int c = 0; for (NodeMeta* n = vault; n; n = n->next) ++c; return c;
    }

    // ────────────────────────────────────────
    // Persist meta to disk  (meta.vtx)
    // ────────────────────────────────────────
    void saveMeta() {
        std::ofstream f(META_FILE, std::ios::binary);
        if (!f) { std::puts("[ERROR] Cannot write meta file."); return; }

        int count = 0;
        for (NodeMeta* c = vault; c; c = c->next) if (c->vitality > -1.0f) ++count;
        f.write(reinterpret_cast<const char*>(&count), sizeof(int));

        for (NodeMeta* c = vault; c; c = c->next) {
            if (c->vitality <= -1.0f) continue;

            f.write(reinterpret_cast<const char*>(&c->id),          sizeof(HexID));
            f.write(reinterpret_cast<const char*>(&c->child_a_id),  sizeof(HexID));
            f.write(reinterpret_cast<const char*>(&c->child_b_id),  sizeof(HexID));
            f.write(reinterpret_cast<const char*>(&c->blob_offset), sizeof(uint64_t));
            f.write(reinterpret_cast<const char*>(&c->vitality),    sizeof(float));
            f.write(reinterpret_cast<const char*>(&c->type),        sizeof(NodeType));
            int pin = c->is_pinned ? 1 : 0;
            f.write(reinterpret_cast<const char*>(&pin),            sizeof(int));

            int dc = static_cast<int>(c->dendrites.size());
            f.write(reinterpret_cast<const char*>(&dc), sizeof(int));
            if (dc > 0)
                f.write(reinterpret_cast<const char*>(c->dendrites.data()), dc * sizeof(HexID));
        }
        // Save blob_eof so we know where to append next time
        f.write(reinterpret_cast<const char*>(&blob_eof), sizeof(uint64_t));

        std::printf("["  "SAVE"  "] Meta persisted (%d nodes). Blob file: %llu bytes.\n",
            count, static_cast<unsigned long long>(blob_eof));
    }

    void loadMeta() {
        std::ifstream f(META_FILE, std::ios::binary);
        if (!f) { std::puts("[PAGER] No meta file found. Fresh vault."); return; }

        // Clear existing
        NodeMeta* c = vault;
        while (c) { NodeMeta* nx = c->next; delete c; c = nx; }
        vault = nullptr; meta_map.clear(); blob_cache.clear(); lru_order.clear();

        int count = 0;
        f.read(reinterpret_cast<char*>(&count), sizeof(int));

        for (int i = 0; i < count; ++i) {
            NodeMeta* m = new NodeMeta;

            f.read(reinterpret_cast<char*>(&m->id),          sizeof(HexID));
            f.read(reinterpret_cast<char*>(&m->child_a_id),  sizeof(HexID));
            f.read(reinterpret_cast<char*>(&m->child_b_id),  sizeof(HexID));
            f.read(reinterpret_cast<char*>(&m->blob_offset), sizeof(uint64_t));
            f.read(reinterpret_cast<char*>(&m->vitality),    sizeof(float));
            f.read(reinterpret_cast<char*>(&m->type),        sizeof(NodeType));
            int pin; f.read(reinterpret_cast<char*>(&pin), sizeof(int));
            m->is_pinned = (pin != 0);

            int dc; f.read(reinterpret_cast<char*>(&dc), sizeof(int));
            m->dendrites.resize(dc);
            if (dc > 0)
                f.read(reinterpret_cast<char*>(m->dendrites.data()), dc * sizeof(HexID));

            m->next = vault; vault = m;
            mapMeta(m);
        }

        f.read(reinterpret_cast<char*>(&blob_eof), sizeof(uint64_t));
        std::printf("["  "LOAD"  "] %d metas loaded. Blob window reset (lazy).\n", count);
    }
};

// ─────────────────────────────────────────────
// Global pager instance
// ─────────────────────────────────────────────
static VaultPager pager;
static History*   history_log = nullptr;

// ─────────────────────────────────────────────
// History
// ─────────────────────────────────────────────
void recordHistory(const HexID& old_id, const HexID& new_id) {
    History* e     = new History;
    e->old_id      = old_id;
    e->new_id      = new_id;
    std::time_t now = std::time(nullptr);
    std::strftime(e->timestamp, 20, "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    e->next        = history_log;
    history_log    = e;
}

// ─────────────────────────────────────────────
// Forward declarations
// ─────────────────────────────────────────────
NodeMeta* ingest(const std::string& text);
void      unrollToBuffer(NodeMeta* m, std::string& out);
void      executeDreamCycle();
void      performCoordinatedMorph();
void      rerouteGrandparents(NodeMeta* old_parent, NodeMeta* new_target);
int       getRank(NodeMeta* m);
int       getNodeHeight(NodeMeta* m);

// ─────────────────────────────────────────────
// Neural split
// ─────────────────────────────────────────────
int findNeuralSplit(const std::string& text) {
    int len = static_cast<int>(text.size());
    if (len <= 4) return len / 2;

    int   weakest = len / 2;
    float minStr  = 2.0f;

    for (int i = 2; i < len - 2; ++i) {
        HexID id_a = hexIDFromStr(text.substr(0, i));
        HexID id_b = hexIDFromStr(text.substr(i));

        NodeMeta* a = pager.findMeta(id_a);
        NodeMeta* b = pager.findMeta(id_b);

        float strength = (a && b) ? std::sqrt(a->vitality * b->vitality) : 0.5f;
        if (text[i] == ' ') strength -= 0.2f;

        if (strength < minStr) { minStr = strength; weakest = i; }
    }
    return weakest;
}

// ─────────────────────────────────────────────
// Ingest
// ─────────────────────────────────────────────
NodeMeta* ingest(const std::string& text) {
    int len = static_cast<int>(text.size());

    // ── ATOM ──
    if (len <= 4) {
        HexID id = hexIDFromStr(text);
        NodeMeta* existing = pager.findMeta(id);
        if (existing) { existing->vitality = 1.0f; return existing; }

        // Write blob to disk
        NodeBlob blob; blob.id = id; blob.lexeme = text;
        uint64_t offset = pager.writeBlob(blob);
        pager.cacheBlob(std::move(blob));   // also hot-cache it

        NodeMeta* m    = new NodeMeta;
        m->id          = id;
        m->type        = NodeType::ATOM;
        m->vitality    = 1.0f;
        m->blob_offset = offset;
        m->next        = pager.vault;
        pager.vault    = m;
        pager.mapMeta(m);
        return m;
    }

    // ── CHUNK ──
    int       split = findNeuralSplit(text);
    NodeMeta* a     = ingest(text.substr(0, split));
    NodeMeta* b     = ingest(text.substr(split));

    HexID cid = computeSHADual(a->id, b->id);
    NodeMeta* existing = pager.findMeta(cid);
    if (existing) {
        existing->vitality = std::min(existing->vitality + 0.1f, 1.0f);
        return existing;
    }

    // Chunks have no lexeme — write a minimal blob
    NodeBlob blob; blob.id = cid;
    uint64_t offset = pager.writeBlob(blob);
    // Don't hot-cache chunk blobs unless requested — save cache for ATOMs

    NodeMeta* m    = new NodeMeta;
    m->id          = cid;
    m->type        = NodeType::CHUNK;
    m->child_a_id  = a->id;
    m->child_b_id  = b->id;
    m->vitality    = std::sqrt(a->vitality * b->vitality);
    m->blob_offset = offset;
    m->next        = pager.vault;
    pager.vault    = m;

    a->dendrites.push_back(cid);
    b->dendrites.push_back(cid);

    pager.mapMeta(m);
    return m;
}

// ─────────────────────────────────────────────
// Unroll  (fetches blobs on demand)
// ─────────────────────────────────────────────
void unroll(NodeMeta* m) {
    if (!m) return;
    if (m->type == NodeType::ATOM) {
        const NodeBlob* b = pager.getBlob(m->id);
        if (b) std::cout << b->lexeme;
    } else {
        unroll(pager.findMeta(m->child_a_id));
        unroll(pager.findMeta(m->child_b_id));
    }
}

void unrollToBuffer(NodeMeta* m, std::string& out) {
    if (!m) return;
    if (m->type == NodeType::ATOM) {
        const NodeBlob* b = pager.getBlob(m->id);
        if (b && out.size() + b->lexeme.size() < MAX_BUF - 1)
            out += b->lexeme;
    } else {
        unrollToBuffer(pager.findMeta(m->child_a_id), out);
        unrollToBuffer(pager.findMeta(m->child_b_id), out);
    }
}

// ─────────────────────────────────────────────
// Reroute grandparents
// ─────────────────────────────────────────────
void rerouteGrandparents(NodeMeta* old_parent, NodeMeta* new_target) {
    if (!old_parent || !new_target || old_parent == new_target) return;
    int routes = 0;
    for (NodeMeta* curr = pager.vault; curr; curr = curr->next) {
        if (curr == new_target) continue;
        bool changed = false;
        if (curr->child_a_id == old_parent->id) { curr->child_a_id = new_target->id; changed = true; }
        if (curr->child_b_id == old_parent->id) { curr->child_b_id = new_target->id; changed = true; }
        for (auto& d : curr->dendrites)
            if (d == old_parent->id) { d = new_target->id; changed = true; }
        if (changed) ++routes;
    }
    if (routes > 0)
        std::printf("["  "HEAL"  "] %d grandparents re-wired.\n", routes);
}

// ─────────────────────────────────────────────
// Rank / Height (meta-only, no disk I/O)
// ─────────────────────────────────────────────
int getRank(NodeMeta* m) {
    if (!m || m->type == NodeType::ATOM) return 0;
    return 1 + std::max(getRank(pager.findMeta(m->child_a_id)),
                        getRank(pager.findMeta(m->child_b_id)));
}

int getNodeHeight(NodeMeta* m) {
    if (!m) return 0;
    if (m->type == NodeType::ATOM) return 1;
    return 1 + std::max(getNodeHeight(pager.findMeta(m->child_a_id)),
                        getNodeHeight(pager.findMeta(m->child_b_id)));
}

int getVaultMaxDepth() {
    int mx = 0;
    for (NodeMeta* c = pager.vault; c; c = c->next)
        mx = std::max(mx, getNodeHeight(c));
    return mx;
}

// ─────────────────────────────────────────────
// Coordinated morph  (meta-only)
// ─────────────────────────────────────────────
void performCoordinatedMorph() {
    std::vector<NodeMeta*> nodes;
    for (NodeMeta* c = pager.vault; c; c = c->next) nodes.push_back(c);

    std::sort(nodes.begin(), nodes.end(), [](NodeMeta* a, NodeMeta* b){
        return getRank(a) < getRank(b);
    });

    for (NodeMeta* m : nodes) {
        if (m->type == NodeType::CHUNK && !m->child_a_id.isNull() && !m->child_b_id.isNull()) {
            HexID old_id = m->id;
            HexID new_id = computeSHADual(m->child_a_id, m->child_b_id);

            if (new_id != old_id) {
                NodeMeta* collision = pager.findMeta(new_id);
                if (collision && collision != m) {
                    recordHistory(m->id, collision->id);
                    rerouteGrandparents(m, collision);
                    m->vitality = -1.0f;
                } else {
                    pager.unmapMeta(old_id);
                    m->id = new_id;
                    pager.mapMeta(m);
                    recordHistory(old_id, new_id);
                }
            }
        }
    }
}

// ─────────────────────────────────────────────
// Dream cycle  (meta-only scan — no disk I/O)
// ─────────────────────────────────────────────
void executeDreamCycle() {
    int stale = 0;
    for (NodeMeta* m = pager.vault; m; m = m->next) {
        if (!m->is_pinned && m->vitality > 0) m->vitality *= DECAY_MULTIPLIER;
        if (m->vitality < DECAY_THRESHOLD || m->vitality < 0) {
            if (!m->dendrites.empty() && m->vitality >= 0) { m->vitality = -2.0f; ++stale; }
            else m->vitality = -1.0f;
        }
    }

    if (stale > 0) {
        std::printf("["  "BATCH"  "] Re-folding %d lineages...\n", stale);
        performCoordinatedMorph();
    }

    NodeMeta** curr = &pager.vault;
    while (*curr) {
        if ((*curr)->vitality <= -1.0f) {
            NodeMeta* old = *curr;
            *curr = (*curr)->next;
            pager.unmapMeta(old->id);
            // NOTE: blob on disk is orphaned (append-log style).
            // A separate compaction pass can reclaim it — see COMPACT command.
            delete old;
        } else {
            curr = &((*curr)->next);
        }
    }
}

// ─────────────────────────────────────────────
// Phoenix redigestion
// ─────────────────────────────────────────────
void phoenixRedigestionProtocol(NodeMeta* target) {
    if (!target) return;

    std::string recovery;
    unrollToBuffer(target, recovery);   // triggers blob loads for ATOMs only
    std::printf("[\033[1;31mPHOENIX\033[0m] Redigesting: \"%s\"\n", recovery.c_str());

    NodeMeta* redigested = ingest(recovery);
    if (redigested == target) {
        std::puts("[\033[1;33mWARN\033[0m] Identical identity. No morph required.");
        return;
    }

    rerouteGrandparents(target, redigested);
    target->vitality  = -1.0f;
    target->is_pinned = false;
    std::puts("[\033[1;32mSUCCESS\033[0m] Redigestion complete.");
}

// ─────────────────────────────────────────────
// Ruminate
// ─────────────────────────────────────────────
void runRuminateLogic(const std::string& targetHex) {
    if (!targetHex.empty()) {
        NodeMeta* target = pager.findMetaFromHexStr(targetHex);
        if (!target) { std::puts("[ERROR] Target Hex not found."); return; }
        std::printf("[\033[1;35mRUMINATE\033[0m] Deep-fold on: %s\n", targetHex.c_str());
        std::string buf; unrollToBuffer(target, buf);
        NodeMeta* nv = ingest(buf);
        if (nv) nv->is_pinned = true;
    } else {
        std::puts("[\033[1;35mRUMINATE\033[0m] Global Pinned Consolidation...");
        int count = 0;
        for (NodeMeta* curr = pager.vault; curr; curr = curr->next) {
            if (curr->dendrites.empty() && curr->is_pinned) {
                std::string buf; unrollToBuffer(curr, buf);
                NodeMeta* nv = ingest(buf);
                if (nv) nv->is_pinned = true;
                ++count;
            }
        }
        std::printf("[INFO] %d roots re-folded.\n", count);
    }
}

// ─────────────────────────────────────────────
// Audit (loads blobs for ATOMs only)
// ─────────────────────────────────────────────
void auditRecursive(NodeMeta* m, int depth, bool last) {
    if (!m) return;
    for (int i = 0; i < depth; ++i) {
        if (i == depth - 1)
            std::printf( "%s" , last ? "└── " : "├── ");
        else
            std::printf( "│   " );
    }
    std::string hex = m->id.toHexStr();
    std::printf("["  "%s"  "] ", hex.c_str());
    std::printf( "V:%.2f"  " ", m->vitality);
    if (m->is_pinned) std::printf( "(PIN) " );
    if (m->type == NodeType::ATOM) {
        const NodeBlob* b = pager.getBlob(m->id);   // disk load if cold
        std::printf( "«%s»" , b ? b->lexeme.c_str() : "?");
    }
    std::putchar('\n');
    if (m->type == NodeType::CHUNK) {
        auditRecursive(pager.findMeta(m->child_a_id), depth + 1, false);
        auditRecursive(pager.findMeta(m->child_b_id), depth + 1, true);
    }
}

// ─────────────────────────────────────────────
// Recover roots  (meta-only)
// ─────────────────────────────────────────────
void recoverRoots() {
    std::puts("\n--- RECOVERING INDEPENDENT NEURAL ROOTS ---");
    for (NodeMeta* curr = pager.vault; curr; curr = curr->next) {
        if (curr->dendrites.empty()) {
            std::printf("Root: ["  "%s"  "] V:"  "%.2f"  " %s\n",
                curr->id.toHexStr().c_str(), curr->vitality,
                curr->is_pinned ?  "PINNED"  :  "VOLATILE" );
        }
    }
}

// ─────────────────────────────────────────────
// Pin
// ─────────────────────────────────────────────
void pinNodeManual(const std::string& hex) {
    NodeMeta* m = pager.findMetaFromHexStr(hex);
    if (m) {
        m->is_pinned = true; m->vitality = 1.0f;
        std::printf("[PIN] Node [%s] is IMMORTAL.\n", hex.c_str());
    } else {
        std::printf("[ERROR] Not found: %s\n", hex.c_str());
    }
}

// ─────────────────────────────────────────────
// History display
// ─────────────────────────────────────────────
void displayHistoryLog() {
    std::printf("\n"  "--- NEURAL LINEAGE HISTORY ---"  "\n");
    if (!history_log) { std::puts("No shifts recorded."); return; }
    for (History* curr = history_log; curr; curr = curr->next) {
        std::printf( "%s"  " | ["  "%s"  "] → ["  "%s"  "]\n",
            curr->timestamp,
            curr->old_id.toHexStr().c_str(),
            curr->new_id.toHexStr().c_str());
    }
}

// ─────────────────────────────────────────────
// Metrics  (meta-only + cache stats)
// ─────────────────────────────────────────────
void displayMetrics() {
    int atoms = pager.countAtoms(), chunks = pager.countChunks();
    int maxDepth = getVaultMaxDepth();

    std::size_t metaRam = static_cast<std::size_t>(atoms + chunks) * sizeof(NodeMeta);
    std::size_t blobRam = pager.blob_cache.size() * sizeof(NodeBlob);
    uint64_t    diskBytes = pager.blob_eof;

    float hitRate = 0.f;
    uint64_t total_access = pager.cache_hits + pager.cache_misses;
    if (total_access > 0)
        hitRate = 100.f * static_cast<float>(pager.cache_hits) / static_cast<float>(total_access);

    std::printf("\n"  "--- NEURAL DENSITY REPORT (PAGED) ---"  "\n");
    std::printf(" Population:      ["  "%d"  "] Atoms | ["  "%d"  "] Chunks\n", atoms, chunks);
    std::printf(" Meta RAM:        "  "%.2f MB"  " (always resident)\n",
        static_cast<float>(metaRam) / (1024*1024));
    std::printf(" Blob Cache RAM:  "  "%.2f MB"  " (%zu/%d hot blobs)\n",
        static_cast<float>(blobRam) / (1024*1024),
        pager.blob_cache.size(), MAX_HOT_BLOBS);
    std::printf(" Blob File Size:  "  "%llu bytes"  " on disk\n",
        static_cast<unsigned long long>(diskBytes));
    std::printf(" Cache Hit Rate:  "  "%.1f%%"  " (%llu hits / %llu misses)\n",
        hitRate,
        static_cast<unsigned long long>(pager.cache_hits),
        static_cast<unsigned long long>(pager.cache_misses));
    std::printf(" Max Tree Depth:  %d\n", maxDepth);
    std::printf(" NodeMeta size:   %zu bytes\n", sizeof(NodeMeta));
    std::puts("--------------------------------------");
}

// ─────────────────────────────────────────────
// Neural Hunt
// ─────────────────────────────────────────────
NodeMeta* getStrongestRoot() {
    NodeMeta* best = nullptr; float maxV = -1.f;
    for (NodeMeta* curr = pager.vault; curr; curr = curr->next)
        if (curr->dendrites.empty() && curr->vitality > maxV) { maxV = curr->vitality; best = curr; }
    return best ? best : pager.vault;
}

void runNeuralHunt(HexID seedId, int maxLen) {
    HexID current = seedId;
    std::printf("\n\033[1;35m[HUNT]: \033[0m");

    for (int i = 0; i < maxLen; ++i) {
        NodeMeta* m = pager.findMeta(current);
        if (!m) break;

        if (m->type == NodeType::ATOM) {
            const NodeBlob* b = pager.getBlob(m->id);
            if (b) std::printf("%s", b->lexeme.c_str());
        }

        std::vector<NodeMeta*> candidates;
        for (NodeMeta* scan = pager.vault; scan; scan = scan->next)
            if (scan->type == NodeType::CHUNK && scan->child_a_id == current) {
                NodeMeta* rb = pager.findMeta(scan->child_b_id);
                if (rb) candidates.push_back(rb);
            }

        if (!candidates.empty()) {
            std::sort(candidates.begin(), candidates.end(), [](NodeMeta* a, NodeMeta* b){
                return b->vitality < a->vitality;
            });
            int k = std::min(static_cast<int>(candidates.size()), 3);
            float total = 0; for (int j = 0; j < k; ++j) total += candidates[j]->vitality;
            float pick = (static_cast<float>(std::rand()) / RAND_MAX) * total;
            float acc  = 0;
            for (int j = 0; j < k; ++j) {
                acc += candidates[j]->vitality;
                if (acc >= pick) { current = candidates[j]->id; break; }
            }
        } else {
            NodeMeta* jumper = pager.vault;
            int dist = std::rand() % 20;
            for (int j = 0; j < dist && jumper && jumper->next; ++j) jumper = jumper->next;
            if (jumper) current = jumper->id; else break;
        }
    }
    std::puts("\n\033[1;36m[SEQUENCE COMPLETE]\033[0m");
}

// ─────────────────────────────────────────────
// Dummy JSON
// ─────────────────────────────────────────────
std::string generateDummyJson(int index) {
    static const char* eyeColors[] = {"blue","brown","green","amber","gray"};
    static const char* fruits[]    = {"apple","banana","strawberry","mango","kiwi"};
    static const char* depts[]     = {"NEURAL_BIO","CYBER_LOGIC","QUANTUM_OPS","VOLTEX_LABS"};

    char buf[2048];
    std::snprintf(buf, sizeof(buf),
        "{\"_id\":\"5f%06x%06x\",\"index\":%d,\"isActive\":%s,"
        "\"balance\":\"$%.2f\",\"age\":%d,\"eyeColor\":\"%s\","
        "\"name\":\"Agent_%d\",\"company\":\"%s\","
        "\"location\":[%.4f,%.4f],\"favoriteFruit\":\"%s\"}",
        std::rand()%0xFFFFFF, std::rand()%0xFFFFFF, index,
        (std::rand()%2) ? "true" : "false",
        1000.f + static_cast<float>(std::rand()%500000)/100.f,
        18 + std::rand()%50,
        eyeColors[std::rand()%5], index, depts[std::rand()%4],
        static_cast<float>(std::rand()%1800000)/10000.f - 90.f,
        static_cast<float>(std::rand()%3600000)/10000.f - 180.f,
        fruits[std::rand()%5]);
    return {buf};
}

// ─────────────────────────────────────────────
// Banner
// ─────────────────────────────────────────────
#ifdef _WIN32
#include <windows.h>
void enableWindowsTerminal() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE); DWORD m = 0;
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &m))
        SetConsoleMode(h, m | 0x0004);
    SetConsoleOutputCP(65001);
}
#endif

void printBanner() {
#ifdef _WIN32 
    enableWindowsTerminal();
#endif
    int   total = pager.countTotal();
    int   maxD  = getVaultMaxDepth();
    float load  = (total / 100000.f) * 100.f;

    std::puts("\n\033[1;30m   ⣎⡇⠀⢠⢠⡀ ─── VOLTEX PAGED NEURAL CORE ───⡇⣱\033[0m");
    std::puts("\033[1;35m   ⚚  V O L T E X  ─╼  N E U R A L _ L S M  ╾─  P A G E R  ⚚\033[0m\n");

    std::printf("   \033[1;30m[ PULSE:\033[1;32mACTIVE\033[1;30m | DEPTH:\033[1;37m%d\033[1;30m | POP:\033[1;33m%d\033[1;30m"
                " | HOT_BLOBS:\033[1;36m%zu/%d\033[1;30m | LOAD:\033[1;31m%.1f%%\033[1;30m ]\033[0m\n",
        maxD, total, pager.blob_cache.size(), MAX_HOT_BLOBS, load);

    std::puts("\n   \033[1;34m╭─ [ SYNTHESIS ]\033[0m");
    std::puts("   \033[1;34m╽\033[1;32m  01 \033[1;37mINGEST    \033[1;30m──╼ \033[0;37mFold → NodeMeta(RAM) + NodeBlob(disk)\033[0m");
    std::puts("   \033[1;34m╽\033[1;32m  02 \033[1;37mUNROLL    \033[1;30m──╼ \033[0;37mReconstruct (lazy blob loads)\033[0m");
    std::puts("   \033[1;34m╽\033[1;32m  03 \033[1;37mAUDIT     \033[1;30m──╼ \033[0;37mTree topology (meta-first)\033[0m");
    std::puts("   \033[1;34m╽\033[1;33m  12 \033[1;37mHUNT      \033[1;30m──╼ \033[0;37mProbabilistic traversal\033[0m");

    std::puts("\n   \033[1;35m╭─ [ METABOLIC ]\033[0m");
    std::puts("   \033[1;35m╽\033[1;35m  04 \033[1;37mDREAM     \033[1;30m──╼ \033[0;37mDecay (meta-only, zero blob I/O)\033[0m");
    std::puts("   \033[1;35m╽\033[1;33m  14 \033[1;37mEVO       \033[1;30m──╼ \033[0;37mBulk JSON ingestion stress test\033[0m");
    std::puts("   \033[1;35m╽\033[1;33m  15 \033[1;37mRUMINATE  \033[1;30m──╼ \033[0;37mConsolidate pinned roots\033[0m");

    std::puts("\n   \033[1;36m╭─ [ ANALYTICS ]\033[0m");
    std::puts("   \033[1;36m╽\033[1;36m  05 \033[1;37mMETRICS   \033[1;30m──╼ \033[0;37mRAM/disk split + cache hit rate\033[0m");
    std::puts("   \033[1;36m╽\033[1;36m  06 \033[1;37mHISTORY   \033[1;30m──╼ \033[0;37mLineage history\033[0m");
    std::puts("   \033[1;36m╽\033[1;37m  10 \033[1;37mSAVE      \033[1;30m──╼ \033[0;37mFlush meta index to vault.meta\033[0m");
    std::puts("   \033[1;36m╽\033[1;37m  11 \033[1;37mLOAD      \033[1;30m──╼ \033[0;37mRestore meta index (blobs lazy)\033[0m");

    std::puts("\n   \033[1;31m╭─ [ SURGERY ]\033[0m");
    std::puts("   \033[1;31m╽\033[1;31m  07 \033[1;37mPHOENIX   \033[1;30m──╼ \033[0;37mRedigestion & healing morph\033[0m");
    std::puts("   \033[1;31m╽\033[1;33m  08 \033[1;37mPIN       \033[1;30m──╼ \033[0;37mImmortality grant\033[0m");
    std::puts("   \033[1;31m╽\033[1;33m  09 \033[1;37mRECOVER   \033[1;30m──╼ \033[0;37mScan independent roots\033[0m");

    std::puts("\n   \033[1;30m╰╼ \033[1;90m 13 \033[1;37mEXIT\033[0m");
    std::printf("\n   \033[1;35m⚡ \033[1;37mNEURAL_PROBE: \033[0m");
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────
int main() {
    std::srand(static_cast<unsigned>(std::time(nullptr)));
    printBanner();

    std::string cmd;
    while (true) {
        std::printf("\n\033[1;32mvoltex_vault#\033[0m ");
        if (!(std::cin >> cmd)) break;

        if (cmd == "HELP" || cmd == "0") {
            printBanner();

        } else if (cmd == "INGEST" || cmd == "1") {
            std::cin.ignore();
            std::printf("Enter data: ");
            std::string buf;
            if (std::getline(std::cin, buf) && !buf.empty()) {
                NodeMeta* res = ingest(buf);
                if (res)
                    std::printf("[INFO] Synthesis Complete.\nRoot ID: \033[1;37m%s\033[0m\n",
                        res->id.toHexStr().c_str());
            } else std::puts("[ERROR] Empty input.");

        } else if (cmd == "UNROLL" || cmd == "2") {
            std::cin.ignore();
            std::printf("Target Hex: ");
            std::string buf;
            if (std::getline(std::cin, buf) && !buf.empty()) {
                NodeMeta* m = pager.findMetaFromHexStr(buf);
                if (m) { unroll(m); std::putchar('\n'); }
                else std::puts("[ERROR] Node not found.");
            } else std::puts("[ERROR] Empty input.");

        } else if (cmd == "AUDIT" || cmd == "3") {
            std::cin.ignore();
            std::printf("Target Hex: ");
            std::string buf;
            if (std::getline(std::cin, buf) && !buf.empty()) {
                std::puts("\n--- VISUALIZING NEURAL TOPOLOGY ---");
                NodeMeta* m = pager.findMetaFromHexStr(buf);
                if (m) auditRecursive(m, 0, true);
                else std::puts("[ERROR] Node not found.");
                std::puts("------------------------------------");
            } else std::puts("[ERROR] Empty input.");

        } else if (cmd == "DREAM" || cmd == "4") {
            std::printf("[PROCESS] Initiating metabolic decay...");
            executeDreamCycle();
            std::puts(" Done.");

        } else if (cmd == "METRICS" || cmd == "5") {
            displayMetrics();

        } else if (cmd == "LOG" || cmd == "6") {
            displayHistoryLog();

        } else if (cmd == "PHOENIX" || cmd == "7") {
            std::string hex; std::cin >> hex;
            NodeMeta* m = pager.findMetaFromHexStr(hex);
            if (m) {
                std::puts("\n\033[1;31m[PHOENIX INITIALIZED]\033[0m");
                int before = pager.countTotal();
                phoenixRedigestionProtocol(m);
                executeDreamCycle();
                int after = pager.countTotal();
                std::printf("\033[1;32m[SURGERY COMPLETE]\033[0m Purged: %d meta nodes\n", before - after);
            } else std::printf("[ERROR] Node [%s] not found.\n", hex.c_str());

        } else if (cmd == "PIN" || cmd == "8") {
            std::string hex; std::cin >> hex;
            pinNodeManual(hex);

        } else if (cmd == "RECOVER" || cmd == "9") {
            recoverRoots();

        } else if (cmd == "SAVE" || cmd == "10") {
            pager.saveMeta();

        } else if (cmd == "LOAD" || cmd == "11") {
            pager.loadMeta();

        } else if (cmd == "HUNT" || cmd == "12") {
            std::cin.ignore();
            std::puts("\n\033[1;36m[HUNT MODE]\033[0m");
            std::puts(" 1. Hex ID   2. Lexeme string");
            std::printf("Option: "); std::string cs; std::getline(std::cin, cs);
            int choice = std::atoi(cs.c_str());
            std::printf("Term: "); std::string term; std::getline(std::cin, term);

            NodeMeta* found = nullptr;
            if (choice == 1) {
                found = pager.findMetaFromHexStr(term);
            } else {
                // Lexeme search requires a blob load per ATOM candidate
                for (NodeMeta* sc = pager.vault; sc; sc = sc->next) {
                    if (sc->type == NodeType::ATOM) {
                        const NodeBlob* b = pager.getBlob(sc->id);
                        if (b && b->lexeme == term) { found = sc; break; }
                    }
                }
            }

            if (!found) {
                std::printf("[SYSTEM] '%s' not found. Sampling strongest root...\n", term.c_str());
                found = getStrongestRoot();
            }

            if (found) {
                std::printf("[SYSTEM] Starting at [%s]\n", found->id.toHexStr().c_str());
                runNeuralHunt(found->id, 20);
            } else std::puts("[ERROR] Vault empty.");

        } else if (cmd == "EXIT" || cmd == "13") {
            std::puts("\033[1;31mShutting down...\033[0m");
            break;

        } else if (cmd == "EVO" || cmd == "14") {
            int iters = 1000;
            std::printf("\n--- VOLTEX SYNTHESIS (%d RECORDS) ---\n", iters);
            for (int i = 1; i <= iters; ++i) {
                NodeMeta* res = ingest(generateDummyJson(i));
                if (res) { res->is_pinned = true; res->vitality = 1.0f; }
                if (i % 100 == 0) {
                    std::printf("\r[%4d/%d] Metas:%d Hot-blobs:%zu",
                        i, iters, pager.countTotal(), pager.blob_cache.size());
                    std::fflush(stdout);
                }
                if (i % 250 == 0) { std::putchar('\n'); displayMetrics(); }
            }
            std::puts("\n--- SYNTHESIS COMPLETE ---");

        } else if (cmd == "RUMINATE" || cmd == "15") {
            std::cin.ignore();
            std::printf("Target Hex (Enter=GLOBAL): "); std::string target; std::getline(std::cin, target);
            std::printf("Cycles: "); std::string cs; std::getline(std::cin, cs);
            int cycles = std::max(1, std::atoi(cs.c_str()));
            for (int i = 0; i < cycles; ++i) {
                std::printf(" Cycle %d/%d... ", i+1, cycles);
                runRuminateLogic(target);
                executeDreamCycle();
                std::puts("done.");
            }
            std::puts("[DONE]"); displayMetrics();

        } else {
            std::printf("Unknown command. Type HELP.\n");
        }
    }

    // Cleanup history
    History* hc = history_log;
    while (hc) { History* nx = hc->next; delete hc; hc = nx; }
    // pager destructor handles NodeMeta cleanup + closes blob file
    return 0;
}
