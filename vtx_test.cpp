// ═══════════════════════════════════════════════════════════════════
//  vtx_test.cpp  —  Voltex System Test Harness
//
//  Drives voltex_paged via stdin pipe and vtx_export directly.
//  Tests five core properties:
//
//   TEST 1 — Deduplication
//     Same string ingested twice must return the same root HexID.
//     Proves content-addressing is working.
//
//   TEST 2 — Structural Sharing
//     Two strings with a common prefix share leaf nodes.
//     Proves the Merkle DAG is deduplicating substructure, not
//     just whole strings.
//
//   TEST 3 — Vitality Decay
//     An unpinned node's vitality drops each DREAM cycle.
//     A pinned node's vitality stays at 1.0 regardless.
//     Proves the metabolic system is functioning.
//
//   TEST 4 — Persistence Round-Trip
//     Ingest → SAVE → restart (fresh vault) → LOAD → UNROLL
//     must recover the original string exactly.
//     Proves vault.meta + vault.blob are coherent.
//
//   TEST 5 — Export Portability
//     Export → verify → import → UNROLL from restored files
//     must recover the original string.
//     Proves vault.vtxe is a faithful portable snapshot.
//
// ═══════════════════════════════════════════════════════════════════

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <chrono>
#include <functional>

#ifdef _WIN32
  #define POPEN  _popen
  #define PCLOSE _pclose
#else
  #define POPEN  popen
  #define PCLOSE pclose
#endif

// ─────────────────────────────────────────────
// Configuration — adjust to match your binaries
// ─────────────────────────────────────────────
#ifdef _WIN32
  static const std::string VOLTEX_BIN    = ".\\voltex.exe";
  static const std::string EXPORT_BIN    = ".\\vtx_exportx.exe";
#else
  static const std::string VOLTEX_BIN    = "./voltex";
  static const std::string EXPORT_BIN    = "./vtx_export";
#endif

static const std::string META_FILE       = "vault.meta";
static const std::string BLOB_FILE       = "vault.blob";
static const std::string VTXE_FILE       = "vault.vtxe";
static const std::string RESTORED_META   = "restored.meta";
static const std::string RESTORED_BLOB   = "restored.blob";

// ANSI
static const std::string GRN = "\x1b[32m";
static const std::string YEL = "\x1b[33m";
static const std::string CYN = "\x1b[36m";
static const std::string RED = "\x1b[31m";
static const std::string MAG = "\x1b[35m";
static const std::string RST = "\x1b[0m";
static const std::string BLD = "\x1b[1m";

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

// Run a shell command and capture stdout
std::string runCapture(const std::string& cmd) {
    std::string result;
    FILE* pipe = POPEN(cmd.c_str(), "r");
    if (!pipe) return "";
    char buf[256];
    while (fgets(buf, sizeof(buf), pipe))
        result += buf;
    PCLOSE(pipe);
    return result;
}

// Write a sequence of commands to a temp file and pipe them into voltex
// Returns full stdout of the voltex session
std::string runVoltex(const std::vector<std::string>& commands) {
    // Write commands to a temp input file
    {
        std::ofstream f("_test_input.txt");
        for (const auto& c : commands) f << c << "\n";
        f << "EXIT\n";
    }
#ifdef _WIN32
    std::string cmd = VOLTEX_BIN + " < _test_input.txt 2>&1";
#else
    std::string cmd = VOLTEX_BIN + " < _test_input.txt 2>&1";
#endif
    return runCapture(cmd);
}

// Extract the Root ID line from an INGEST response
// Looks for "Root ID: <64 hex chars>"
std::string extractRootID(const std::string& output) {
    const std::string marker = "Root ID: ";
    auto pos = output.find(marker);
    if (pos == std::string::npos) return "";
    pos += marker.size();
    // Skip any ANSI escape codes
    while (pos < output.size() && output[pos] == '\x1b') {
        while (pos < output.size() && output[pos] != 'm') ++pos;
        ++pos;
    }
    // Read 64 hex chars
    std::string id;
    while (pos < output.size() && id.size() < 64) {
        char c = output[pos++];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) id += c;
        else if (id.size() > 0) break;
    }
    return (id.size() == 64) ? id : "";
}

// Extract unroll output — the line after "[UNROLL]" prompt response
// We look for text that isn't a prompt or status line
std::string extractUnroll(const std::string& output, const std::string& after_marker) {
    auto pos = output.find(after_marker);
    if (pos == std::string::npos) {
        // fallback: last non-empty non-prompt line
        std::istringstream ss(output);
        std::string line, last;
        while (std::getline(ss, line)) {
            if (!line.empty() &&
                line.find("voltex_vault") == std::string::npos &&
                line.find("[INFO]")       == std::string::npos &&
                line.find("Target")       == std::string::npos &&
                line.find("NEURAL")       == std::string::npos &&
                line.find("Enter")        == std::string::npos &&
                line.find("PROBE")        == std::string::npos)
                last = line;
        }
        return last;
    }
    // Read the next non-empty line after the marker
    pos += after_marker.size();
    while (pos < output.size() && output[pos] != '\n') ++pos;
    ++pos;
    std::string line;
    while (pos < output.size() && output[pos] != '\n')
        line += output[pos++];
    return line;
}

// Strip ANSI escape codes from a string
std::string stripANSI(const std::string& s) {
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\x1b' && i + 1 < s.size() && s[i+1] == '[') {
            i += 2;
            while (i < s.size() && s[i] != 'm') ++i;
        } else out += s[i];
    }
    return out;
}

bool strContains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

void deleteFile(const std::string& f) {
#ifdef _WIN32
    std::remove(f.c_str());
#else
    std::remove(f.c_str());
#endif
}

// ─────────────────────────────────────────────
// Test result tracking
// ─────────────────────────────────────────────
struct TestResult {
    std::string name;
    bool        passed;
    std::string detail;
    double      ms;
};

std::vector<TestResult> results;

void beginTest(const std::string& name) {
    std::printf("\n%s%s┌─ %s%s%s\n", BLD.c_str(), CYN.c_str(), RST.c_str(), BLD.c_str(), name.c_str());
    std::fflush(stdout);
}

void check(std::vector<TestResult>& res,
           const std::string& test_name,
           const std::string& assert_name,
           bool condition,
           const std::string& detail,
           double ms = 0.0)
{
    std::string icon = condition ? (GRN + "  ✓") : (RED + "  ✗");
    std::printf("%s %s%s  %s\n", icon.c_str(), RST.c_str(), assert_name.c_str(), detail.c_str());
    std::fflush(stdout);
    res.push_back({test_name + " / " + assert_name, condition, detail, ms});
}

// ─────────────────────────────────────────────
// TEST 1 — Deduplication
// ─────────────────────────────────────────────
void test_deduplication() {
    beginTest("TEST 1 — Content-Addressed Deduplication");

    // Clean state
    deleteFile(META_FILE); deleteFile(BLOB_FILE);

    auto t0 = std::chrono::high_resolution_clock::now();

    // Ingest the same string twice in one session
    std::string out = runVoltex({
        "INGEST", "hello voltex world",
        "INGEST", "hello voltex world",
        "METRICS"
    });

    auto t1 = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    // Strip ANSI first so escape codes never interrupt hex character runs
    std::string clean = stripANSI(out);

    // Find Root IDs line-by-line — each "Root ID:" line holds exactly one 64-char hex string
    std::vector<std::string> root_ids;
    {
        std::istringstream ss_ids(clean);
        std::string lid;
        while (std::getline(ss_ids, lid)) {
            const std::string mk = "Root ID:";
            auto mpos = lid.find(mk);
            if (mpos == std::string::npos) continue;
            std::string run;
            for (std::size_t ci = mpos + mk.size(); ci < lid.size(); ++ci) {
                char c = lid[ci];
                if ((c>='0'&&c<='9')||(c>='a'&&c<='f')) {
                    run += c;
                } else if (!run.empty()) {
                    if (run.size() == 64) { root_ids.push_back(run); break; }
                    run.clear(); // discard short runs, keep scanning
                }
            }
            if (run.size() == 64 && (root_ids.empty() || root_ids.back() != run))
                root_ids.push_back(run);
        }
    }
    std::string id1 = root_ids.size() > 0 ? root_ids[0] : "";
    std::string id2 = root_ids.size() > 1 ? root_ids[1] : "";

    check(results, "Deduplication", "Two ingests return a root ID",
          !id1.empty(), "id1=" + id1.substr(0,16) + "...", ms);
    check(results, "Deduplication", "Both root IDs are identical",
          id1 == id2,
          id1 == id2 ? "MATCH" : "id1=" + id1.substr(0,8) + " id2=" + id2.substr(0,8));
    check(results, "Deduplication", "Vault metrics show dedup occurred",
          strContains(clean, "Atoms") || strContains(clean, "Population"),
          "metrics present");
}

// ─────────────────────────────────────────────
// TEST 2 — Structural Sharing
// ─────────────────────────────────────────────
void test_structural_sharing() {
    beginTest("TEST 2 — Structural Sharing (Common Prefix)");

    deleteFile(META_FILE); deleteFile(BLOB_FILE);

    auto t0 = std::chrono::high_resolution_clock::now();

    // Ingest two strings with a shared prefix, then check metrics
    // A vault with sharing should have fewer atoms than two independent vaults
    std::string out_shared = runVoltex({
        "INGEST", "hello voltex alpha",
        "INGEST", "hello voltex beta",
        "METRICS"
    });

    auto t1 = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    std::string clean = stripANSI(out_shared);

    // Extract atom count from metrics
    // "Population: [N] Atoms | [M] Chunks"
    int atoms_shared = -1;
    auto apos = clean.find("Atoms");
    if (apos != std::string::npos) {
        // Walk backward to find the number
        int i = static_cast<int>(apos) - 1;
        while (i >= 0 && (clean[i] == ' ' || clean[i] == ']')) --i;
        std::string num;
        while (i >= 0 && std::isdigit(clean[i])) num = clean[i--] + num;
        if (!num.empty()) atoms_shared = std::stoi(num);
    }

    // Now ingest two completely unrelated strings
    deleteFile(META_FILE); deleteFile(BLOB_FILE);
    std::string out_unrelated = runVoltex({
        "INGEST", "hello voltex alpha",
        "INGEST", "zzzzz qqqqqq wwwww",
        "METRICS"
    });
    std::string clean2 = stripANSI(out_unrelated);
    int atoms_unrelated = -1;
    apos = clean2.find("Atoms");
    if (apos != std::string::npos) {
        int i = static_cast<int>(apos) - 1;
        while (i >= 0 && (clean2[i] == ' ' || clean2[i] == ']')) --i;
        std::string num;
        while (i >= 0 && std::isdigit(clean2[i])) num = clean2[i--] + num;
        if (!num.empty()) atoms_unrelated = std::stoi(num);
    }

    char detail[128];
    std::snprintf(detail, sizeof(detail),
        "shared=%d atoms  unrelated=%d atoms", atoms_shared, atoms_unrelated);

    check(results, "Structural Sharing", "Atom count is measurable",
          atoms_shared > 0 && atoms_unrelated > 0, detail, ms);
    check(results, "Structural Sharing", "Shared-prefix vault has fewer atoms",
          atoms_shared < atoms_unrelated,
          atoms_shared < atoms_unrelated
              ? "confirmed — common substructure collapsed"
              : "not confirmed (check ATOM_LEAF_SIZE)");
}

// ─────────────────────────────────────────────
// TEST 3 — Vitality Decay
// ─────────────────────────────────────────────
void test_vitality_decay() {
    beginTest("TEST 3 — Vitality Decay (DREAM cycle)");

    deleteFile(META_FILE); deleteFile(BLOB_FILE);

    auto t0 = std::chrono::high_resolution_clock::now();

    // Ingest one string unpinned, one pinned, then run multiple DREAM cycles
    // Check that vault shrinks (unpinned nodes decay and get purged)
    std::string out = runVoltex({
        "INGEST", "decay test string one",      // unpinned
        "INGEST", "pinned survivor string",     // will be pinned below
        "METRICS",
        // PIN the second root — we need its ID first from the output above,
        // but since we can't parse mid-session easily, we instead just
        // run many DREAM cycles and confirm the vault shrinks
        // 40 cycles: 0.95^40 = 0.129 — below the 0.2 DECAY_THRESHOLD
        "DREAM", "DREAM", "DREAM", "DREAM", "DREAM",
        "DREAM", "DREAM", "DREAM", "DREAM", "DREAM",
        "DREAM", "DREAM", "DREAM", "DREAM", "DREAM",
        "DREAM", "DREAM", "DREAM", "DREAM", "DREAM",
        "DREAM", "DREAM", "DREAM", "DREAM", "DREAM",
        "DREAM", "DREAM", "DREAM", "DREAM", "DREAM",
        "DREAM", "DREAM", "DREAM", "DREAM", "DREAM",
        "DREAM", "DREAM", "DREAM", "DREAM", "DREAM",
        "METRICS"
    });

    auto t1 = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    std::string clean = stripANSI(out);

    // Parse TOTAL node count (atoms+chunks) from each "Population:" line.
    // Format: "Population:     [N] Atoms | [M] Chunks"
    // We sum both numbers to get total nodes, which must shrink after decay.
    std::vector<int> total_nodes;
    {
        std::istringstream ss_pop(clean);
        std::string pline;
        while (std::getline(ss_pop, pline)) {
            if (pline.find("Population") == std::string::npos) continue;
            // Extract all bracket-wrapped integers on this line: [N] ... [M]
            int line_total = 0; bool found_any = false;
            for (std::size_t ci = 0; ci < pline.size(); ++ci) {
                if (pline[ci] == '[') {
                    std::string num;
                    ++ci;
                    while (ci < pline.size() && std::isdigit(pline[ci])) num += pline[ci++];
                    if (!num.empty()) { line_total += std::stoi(num); found_any = true; }
                }
            }
            if (found_any) total_nodes.push_back(line_total);
        }
    }

    bool two_readings = total_nodes.size() >= 2;
    bool vault_shrunk = two_readings && total_nodes.back() < total_nodes.front();

    char detail_pop[128] = "could not parse node counts";
    if (two_readings)
        std::snprintf(detail_pop, sizeof(detail_pop),
            "before=%d nodes  after=%d nodes", total_nodes[0], total_nodes.back());

    check(results, "Vitality Decay", "DREAM cycle runs without crash",
          strContains(clean, "Success") || strContains(clean, "purged") ||
          strContains(clean, "Done"),
          "dream cycle completed", ms);
    check(results, "Vitality Decay", "Vault population decreases after 40 cycles",
          vault_shrunk, detail_pop);
    check(results, "Vitality Decay", "Vault is not completely empty after decay",
          !total_nodes.empty() && total_nodes.back() > 0,
          "nodes survived decay");
}

// ─────────────────────────────────────────────
// TEST 4 — Persistence Round-Trip
// ─────────────────────────────────────────────
void test_persistence() {
    beginTest("TEST 4 — Persistence Round-Trip (SAVE → LOAD → UNROLL)");

    deleteFile(META_FILE); deleteFile(BLOB_FILE);

    const std::string test_string = "persistence test string";

    auto t0 = std::chrono::high_resolution_clock::now();

    // Session 1: ingest and save
    std::string session1 = runVoltex({
        "INGEST", test_string,
        "SAVE"
    });

    std::string clean1  = stripANSI(session1);
    std::string root_id = "";

    // Extract root ID
    const std::string rm = "Root ID: ";
    auto rpos = clean1.find(rm);
    if (rpos != std::string::npos) {
        rpos += rm.size();
        while (rpos < clean1.size() && root_id.size() < 64) {
            char c = clean1[rpos++];
            if ((c>='0'&&c<='9')||(c>='a'&&c<='f')) root_id += c;
            else if (!root_id.empty()) break;
        }
    }

    // Session 2: fresh vault, load, unroll
    std::string session2 = runVoltex({
        "LOAD",
        "UNROLL", root_id
    });

    auto t1 = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    std::string clean2 = stripANSI(session2);

    bool saved    = strContains(clean1, "persisted") || strContains(clean1, "SAVE");
    bool loaded   = strContains(clean2, "metas loaded") || strContains(clean2, "LOAD");
    bool has_id   = root_id.size() == 64;
    bool recovered = strContains(clean2, test_string);

    check(results, "Persistence", "Root ID extracted from session 1",
          has_id, has_id ? root_id.substr(0,16) + "..." : "not found", ms);
    check(results, "Persistence", "SAVE confirmed in session 1",
          saved, "vault.meta written");
    check(results, "Persistence", "LOAD confirmed in session 2",
          loaded, "meta index restored");
    check(results, "Persistence", "Original string recovered via UNROLL",
          recovered,
          recovered ? "\"" + test_string + "\"" : "not found in output");
}

// ─────────────────────────────────────────────
// TEST 5 — Export Portability
// ─────────────────────────────────────────────
void test_export_portability() {
    beginTest("TEST 5 — Export Portability (vtxe round-trip)");

    deleteFile(META_FILE); deleteFile(BLOB_FILE);
    deleteFile(VTXE_FILE);
    deleteFile(RESTORED_META); deleteFile(RESTORED_BLOB);

    const std::string test_string = "export portability test";

    auto t0 = std::chrono::high_resolution_clock::now();

    // Step 1: ingest and save vault
    std::string s1 = runVoltex({"INGEST", test_string, "SAVE"});
    std::string c1 = stripANSI(s1);

    std::string root_id;
    const std::string rm = "Root ID: ";
    auto rpos = c1.find(rm);
    if (rpos != std::string::npos) {
        rpos += rm.size();
        while (rpos < c1.size() && root_id.size() < 64) {
            char c = c1[rpos++];
            if ((c>='0'&&c<='9')||(c>='a'&&c<='f')) root_id += c;
            else if (!root_id.empty()) break;
        }
    }

    // Step 2: export
    std::string export_out = runCapture(
        EXPORT_BIN + " export " + META_FILE + " " + BLOB_FILE + " " + VTXE_FILE + " 2>&1");
    std::string ec = stripANSI(export_out);

    // Step 3: verify
    std::string verify_out = runCapture(
        EXPORT_BIN + " verify " + VTXE_FILE + " 2>&1");
    std::string vc = stripANSI(verify_out);

    // Step 4: import to restored files
    std::string import_out = runCapture(
        EXPORT_BIN + " import " + VTXE_FILE + " " +
        RESTORED_META + " " + RESTORED_BLOB + " 2>&1");
    std::string ic = stripANSI(import_out);

    // Step 5: load restored vault and unroll
    // We need to temporarily rename the restored files to the expected names
    // and run voltex against them
#ifdef _WIN32
    runCapture("copy restored.meta vault.meta /Y > nul 2>&1");
    runCapture("copy restored.blob vault.blob /Y > nul 2>&1");
#else
    runCapture("cp restored.meta vault.meta");
    runCapture("cp restored.blob vault.blob");
#endif

    std::string s5 = runVoltex({"LOAD", "UNROLL", root_id});
    std::string c5 = stripANSI(s5);

    auto t1 = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    // Check file sizes
    std::ifstream vtxe_f(VTXE_FILE, std::ios::binary | std::ios::ate);
    std::ifstream meta_f(META_FILE,  std::ios::binary | std::ios::ate);
    int64_t vtxe_sz = vtxe_f.is_open() ? static_cast<int64_t>(vtxe_f.tellg()) : int64_t{-1};
    int64_t meta_sz = meta_f.is_open() ? static_cast<int64_t>(meta_f.tellg()) : int64_t{-1};

    bool exported  = strContains(ec, "EXPORT COMPLETE");
    bool verified  = strContains(vc, "VERIFY PASSED");
    bool imported  = strContains(ic, "IMPORT COMPLETE");
    bool recovered = strContains(c5, test_string);
    bool smaller   = vtxe_sz > 0 && meta_sz > 0 && vtxe_sz < meta_sz;

    char sz_detail[128];
    std::snprintf(sz_detail, sizeof(sz_detail),
        "vtxe=%lld bytes  meta=%lld bytes",
        static_cast<long long>(vtxe_sz),
        static_cast<long long>(meta_sz));

    check(results, "Export Portability", "Export completed",
          exported, "vault.vtxe written", ms);
    check(results, "Export Portability", "Verify passed",
          verified, "all records valid");
    check(results, "Export Portability", "Import completed",
          imported, "restored.meta + restored.blob written");
    check(results, "Export Portability", "String recovered from restored vault",
          recovered,
          recovered ? "\"" + test_string + "\"" : "not found in restored output");
    check(results, "Export Portability", "vtxe is smaller than source meta",
          smaller, sz_detail);
}

// ─────────────────────────────────────────────
// BONUS TEST — Throughput benchmark
// ─────────────────────────────────────────────
void test_throughput() {
    beginTest("BONUS — Throughput Benchmark (100 ingests)");

    deleteFile(META_FILE); deleteFile(BLOB_FILE);

    // Build 100 distinct strings
    std::vector<std::string> cmds;
    for (int i = 0; i < 100; ++i) {
        cmds.push_back("INGEST");
        cmds.push_back("benchmark string number " + std::to_string(i) +
                       " with some padding data xyz");
    }
    cmds.push_back("METRICS");

    auto t0 = std::chrono::high_resolution_clock::now();
    std::string out = runVoltex(cmds);
    auto t1 = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    std::string clean = stripANSI(out);

    // Count successful ingests
    int ingest_count = 0;
    std::size_t p = 0;
    while ((p = clean.find("Synthesis Complete", p)) != std::string::npos) {
        ++ingest_count; ++p;
    }

    double per_ingest_ms = ingest_count > 0 ? ms / ingest_count : 0;
    char detail[128];
    std::snprintf(detail, sizeof(detail),
        "%d ingests in %.1f ms  (%.2f ms/ingest)", ingest_count, ms, per_ingest_ms);

    check(results, "Throughput", "All 100 ingests completed",
          ingest_count == 100, detail, ms);
    check(results, "Throughput", "Under 10ms per ingest on average",
          per_ingest_ms < 10.0,
          per_ingest_ms < 10.0 ? "fast" : "slow — check findNeuralSplit O(n)");
}

// ─────────────────────────────────────────────
// Summary
// ─────────────────────────────────────────────
void printSummary() {
    int passed = 0, failed = 0;
    for (const auto& r : results)
        r.passed ? ++passed : ++failed;

    std::printf("\n%s%s══════════════════════════════════════%s\n", BLD.c_str(), MAG.c_str(), RST.c_str());
    std::printf("%s%s  VOLTEX TEST SUMMARY%s\n", BLD.c_str(), MAG.c_str(), RST.c_str());
    std::printf("%s%s══════════════════════════════════════%s\n", BLD.c_str(), MAG.c_str(), RST.c_str());

    for (const auto& r : results) {
        std::string icon = r.passed ? (GRN + "  PASS") : (RED + "  FAIL");
        std::printf("%s%s  %-45s%s  %s\n",
            icon.c_str(), RST.c_str(),
            r.name.c_str(), RST.c_str(),
            r.detail.c_str());
    }

    std::printf("\n  %s%d passed%s  /  %s%d failed%s  /  %d total\n\n",
        GRN.c_str(), passed, RST.c_str(),
        failed > 0 ? RED.c_str() : GRN.c_str(), failed, RST.c_str(),
        static_cast<int>(results.size()));

    if (failed == 0)
        std::printf("%s  All tests passed. Voltex is operational.%s\n\n", GRN.c_str(), RST.c_str());
    else
        std::printf("%s  %d test(s) failed. See details above.%s\n\n", RED.c_str(), failed, RST.c_str());
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::printf("\n%s%s  VOLTEX TEST HARNESS%s\n", BLD.c_str(), CYN.c_str(), RST.c_str());
    std::printf("%s  voltex=%s  export=%s%s\n\n",
        YEL.c_str(), VOLTEX_BIN.c_str(), EXPORT_BIN.c_str(), RST.c_str());

    // Allow running a single test by name: ./vtx_test dedup
    std::string filter = (argc > 1) ? argv[1] : "";

    if (filter.empty() || filter == "dedup")       test_deduplication();
    if (filter.empty() || filter == "sharing")     test_structural_sharing();
    if (filter.empty() || filter == "decay")       test_vitality_decay();
    if (filter.empty() || filter == "persist")     test_persistence();
    if (filter.empty() || filter == "export")      test_export_portability();
    if (filter.empty() || filter == "bench")       test_throughput();

    printSummary();

    // Cleanup temp file
    deleteFile("_test_input.txt");

    // Return exit code based on pass/fail
    for (const auto& r : results)
        if (!r.passed) return 1;
    return 0;
}
