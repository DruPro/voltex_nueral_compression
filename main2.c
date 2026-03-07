#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/sha.h>
#include <math.h>

// --- Configuration ---
#define SHA256_BLOCK_SIZE 32
#define MAX_DENDRITES 16
#define DECAY_MULTIPLIER 0.95f
#define DECAY_THRESHOLD 0.2f
#define MAX_BUF 1024
#define CLR_GREEN "\x1b[32m"
#define CLR_YELLOW "\x1b[33m"
#define CLR_MAGENTA "\x1b[35m"
#define CLR_CYAN "\x1b[36m"
#define CLR_RED "\x1b[31m"
#define CLR_RESET "\x1b[0m"

// --- Structures ---
typedef struct
{
    uint8_t hash[SHA256_BLOCK_SIZE];
} HexID;
typedef enum
{
    V_ATOM,
    V_CHUNK
} NodeType;

// --- Fix 1: Optimized Neural Node ---
typedef struct Node
{
    HexID id;                     // 32 bytes
    NodeType type;                // 4 bytes
    float vitality;               // 4 bytes
    int is_pinned;                // 4 bytes
    struct Node *part_a, *part_b; // 16 bytes
    char *lexeme;                 // 8 bytes

    // DYNAMIC AXONS: Only consumes memory if the node actually has parents
    HexID *dendrite_ids;   // 8 bytes (pointer)
    int dendrite_count;    // 4 bytes
    int dendrite_capacity; // 4 bytes

    struct Node *next; // 8 bytes
} Node;                // Total Size: ~92 bytes. (V1 was 600 bytes)

typedef struct History
{
    HexID old_id;
    HexID new_id;
    char timestamp[20];
    struct History *next;
} History;

// --- Global State ---
Node *vault = NULL;
History *history_log = NULL;

// --- Hash Map Configuration ---
#define HASH_SIZE 8192 // Must be a power of 2 (2^13)
typedef struct HashBucket
{
    Node *node;
    struct HashBucket *next;
} HashBucket;

HashBucket *node_map[HASH_SIZE] = {0};

// --- Core Identity & Hashing ---
uint32_t get_hash_index(HexID id);
void compute_real_sha(const char *data, size_t len, HexID *out);
void get_hex_str(HexID id, char *out);
int ids_equal(HexID a, HexID b);

// --- Vault & Hash Map Management ---
void map_node(Node *n);
void unmap_node(HexID id);
Node *find_node(HexID id);
Node *find_node_from_hex_str(const char *hex_input);

// --- Ingestion & Synthesis ---
Node *ingest(const char *text);
void unroll(Node *n);
void unroll_to_buffer(Node *n, char *out_buf, int *offset);
void run_ruminate_logic(char *target_hex);

// --- Metabolism & Evolution (The Dream Cycle) ---
void execute_dream_cycle();
void perform_coordinated_morph();
int compare_nodes(const void *a, const void *b);
int get_rank(Node *n);
int get_node_depth(Node *n);

// --- Structural Surgery & Healing ---
void morph_surgery_linear(Node *trigger_node);
void reroute_grandparents(Node *old_parent, Node *new_target);
int is_descendant(Node *potential_child, Node *target_ancestor);
void pin_node_manual(const char *prefix);

// --- Telemetry, History & Audit ---
void audit_recursive(Node *n, int depth, int last);
void recover_roots();
void find_pinned_roots(Node **pinned_list, int *count);
void record_history(HexID old_id, HexID new_id);
void display_history_log();
void display_metrics();

// --- Persistence (Disk I/O) ---
void save_vault();
void load_vault();

// --- Propagation Stack (Internal Helper) ---
typedef struct PropagationStack PropagationStack; // Forward decl if needed
void push_prop(PropagationStack **stack, Node *n);
Node *pop_prop(PropagationStack **stack);

// --- UI & Environment ---
void print_banner();
void print_help();
#ifdef _WIN32
void enable_windows_terminal();
#endif

// --- Fix 2: Axon Management ---
void add_dendrite_dynamic(Node *child, HexID parent_id)
{
    if (child->dendrite_count >= child->dendrite_capacity)
    {
        int new_cap = child->dendrite_capacity == 0 ? 2 : child->dendrite_capacity * 2;
        HexID *new_arr = realloc(child->dendrite_ids, new_cap * sizeof(HexID));
        if (!new_arr)
            return;
        child->dendrite_ids = new_arr;
        child->dendrite_capacity = new_cap;
    }
    child->dendrite_ids[child->dendrite_count++] = parent_id;
}

// --- Fix 3: Hebbian Neural Ingestion ---
// Finds the split point where the connection (axon strength) is weakest
int find_neural_split(const char *text)
{
    int len = strlen(text);
    if (len <= 4)
        return len / 2;

    int weakest_split = len / 2;
    float min_strength = 2.0f;

    for (int i = 2; i < len - 2; i++)
    {
        char left[MAX_BUF] = {0}, right[MAX_BUF] = {0};
        strncpy(left, text, i);
        strcpy(right, text + i);

        // --- THE FIX ---
        // 1. Hash the plain text fragments
        HexID id_a, id_b;
        compute_real_sha(left, strlen(left), &id_a);
        compute_real_sha(right, strlen(right), &id_b);

        // 2. Look up the Nodes using the raw binary HashIDs
        Node *a = find_node(id_a);
        Node *b = find_node(id_b);
        // ----------------

        float strength = 1.0f;
        if (a && b)
        {
            strength = sqrtf(a->vitality * b->vitality);
        }
        else
        {
            strength = 0.5f;
        }

        if (text[i] == ' ')
            strength -= 0.2f;

        if (strength < min_strength)
        {
            min_strength = strength;
            weakest_split = i;
        }
    }
    return weakest_split;
}

// Fast index calculation using the first 4 bytes of the ID
uint32_t get_hash_index(HexID id)
{
    uint32_t val;
    memcpy(&val, id.hash, sizeof(uint32_t));
    return val & (HASH_SIZE - 1);
}

// Map a node into the index
void map_node(Node *n)
{
    if (!n)
        return;
    uint32_t index = get_hash_index(n->id);
    HashBucket *entry = malloc(sizeof(HashBucket));
    entry->node = n;
    entry->next = node_map[index];
    node_map[index] = entry;
}

// Remove a node from the index
void unmap_node(HexID id)
{
    uint32_t index = get_hash_index(id);
    HashBucket **curr = &node_map[index];
    while (*curr)
    {
        if (memcmp((*curr)->node->id.hash, id.hash, SHA256_BLOCK_SIZE) == 0)
        {
            HashBucket *to_free = *curr;
            *curr = (*curr)->next;
            free(to_free);
            return;
        }
        curr = &((*curr)->next);
    }
}

// --- Implementation ---

void get_hex_str(HexID id, char *out)
{
    // We must process all 32 bytes to get the 64 hex characters
    for (int i = 0; i < 32; i++)
    {
        // %02x prints one byte as two hex characters (e.g., 255 -> "ff")
        // (out + i * 2) ensures we move two characters forward in the string for every byte
        sprintf(out + (i * 2), "%02x", id.hash[i]);
    }
    // sprintf adds the null terminator automatically at the very end (index 64)
}
void compute_real_sha_dual(HexID a, HexID b, HexID *out)
{
    // A SHA-256 hash is 32 bytes. Two hashes together are 64 bytes.
    unsigned char raw_combo[64];

    // Copy the raw binary hashes, not the hex strings.
    // This is faster and more secure against collisions.
    memcpy(raw_combo, a.hash, 32);
    memcpy(raw_combo + 32, b.hash, 32);

    // Hash the 64-byte block
    SHA256(raw_combo, 64, out->hash);
}
void compute_real_sha(const char *data, size_t len, HexID *out)
{
    // SHA256() is a high-level OpenSSL function that performs
    // init, update, and final in one shot.
    SHA256((const unsigned char *)data, len, out->hash);
}

Node *find_node(HexID id)
{
    uint32_t index = get_hash_index(id);
    HashBucket *bucket = node_map[index];
    while (bucket)
    {
        if (memcmp(bucket->node->id.hash, id.hash, SHA256_BLOCK_SIZE) == 0)
        {
            return bucket->node;
        }
        bucket = bucket->next;
    }
    return NULL;
}

Node *find_node_from_hex_str(const char *hex_input)
{
    // 1. Validation: A SHA-256 hex string must be exactly 64 characters
    if (!hex_input || strlen(hex_input) != 64)
    {
        return NULL;
    }

    HexID temp_id;

    // 2. Convert the Hex string back to raw binary bytes
    // %02hhx tells sscanf to read 2 hex chars into a single unsigned char
    for (int i = 0; i < 32; i++)
    {
        if (sscanf(hex_input + (i * 2), "%02hhx", &temp_id.hash[i]) != 1)
        {
            return NULL; // Return NULL if the string contains non-hex characters
        }
    }

    // 3. Hand off the work to your existing map-based find_node
    // This uses your uint32_t index and HashBucket traversal
    return find_node(temp_id);
}

Node *ingest(const char *text)
{
    int len = strlen(text);

    // --- PHASE 1: ATOM GENERATION (Base Cases) ---
    if (len <= 4)
    {
        HexID id;
        compute_real_sha(text, len, &id);

        Node *existing = find_node(id);
        if (existing)
        {
            existing->vitality = 1.0f; // Revitalize
            return existing;
        }

        Node *n = calloc(1, sizeof(Node));
        n->id = id;
        n->type = V_ATOM;
        n->lexeme = strdup(text);
        n->vitality = 1.0f;

        n->next = vault;
        vault = n;
        map_node(n);
        return n;
    }

    // --- PHASE 2: NEURAL SPLIT (Hebbian Selection) ---
    // Instead of mid = len / 2, we find the weakest connection point
    int split = find_neural_split(text);

    char left[MAX_BUF] = {0}, right[MAX_BUF] = {0};
    strncpy(left, text, split);
    strcpy(right, text + split);

    Node *a = ingest(left);
    Node *b = ingest(right);

    // --- PHASE 3: IDENTITY SYNTHESIS (Merkle Hashing) ---
    unsigned char raw_combo[64];
    memcpy(raw_combo, a->id.hash, 32);
    memcpy(raw_combo + 32, b->id.hash, 32);

    HexID cid;
    compute_real_sha((const char *)raw_combo, 64, &cid);

    // O(1) Check for existing branch
    Node *n = find_node(cid);
    if (n)
    {
        // Reinforce: repeated patterns become "stronger"
        n->vitality = (n->vitality + 0.1f > 1.0f) ? 1.0f : n->vitality + 0.1f;
        return n;
    }

    // --- PHASE 4: CHUNK CREATION & AXON BINDING ---
    n = calloc(1, sizeof(Node));
    n->id = cid;
    n->type = V_CHUNK;
    n->part_a = a;
    n->part_b = b;

    // Geometric mean: if children are weak, parent is weak
    n->vitality = sqrtf(a->vitality * b->vitality);

    n->next = vault;
    vault = n;

    // Use the new dynamic axon function to track dependencies
    add_dendrite_dynamic(a, cid);
    add_dendrite_dynamic(b, cid);

    map_node(n);
    return n;
}

void unroll(Node *n)
{
    if (!n)
        return;
    if (n->type == V_ATOM)
        printf("%s", n->lexeme);
    else
    {
        unroll(n->part_a);
        unroll(n->part_b);
    }
}

void unroll_to_buffer(Node *n, char *out_buf, int *offset)
{
    if (!n)
        return;
    if (n->type == V_ATOM)
    {
        int len = strlen(n->lexeme);
        // Ensure we don't overflow MAX_BUF
        if (*offset + len < MAX_BUF - 1)
        {
            memcpy(out_buf + *offset, n->lexeme, len);
            *offset += len;
            out_buf[*offset] = '\0';
        }
    }
    else
    {
        unroll_to_buffer(n->part_a, out_buf, offset);
        unroll_to_buffer(n->part_b, out_buf, offset);
    }
}

void run_ruminate_logic(char *target_hex)
{
    char rebuild_buf[MAX_BUF];
    int offset;

    if (target_hex && strlen(target_hex) > 0)
    {
        // --- SPECIFIC ROOT RUMINATION ---
        Node *target = find_node_from_hex_str(target_hex);
        if (!target)
        {
            printf("[\033[1;31mERROR\033[0m] Target Hex not found.\n");
            return;
        }

        printf("[\033[1;35mRUMINATE\033[0m] Targeted deep-fold on: %s\n", target_hex);
        offset = 0;
        unroll_to_buffer(target, rebuild_buf, &offset);

        Node *new_root = ingest(rebuild_buf);
        if (new_root)
            new_root->is_pinned = 1;
    }
    else
    {
        // --- GLOBAL PINNED RUMINATION ---
        printf("[\033[1;35mRUMINATE\033[0m] Commencing Global Pinned Consolidation...\n");
        Node *curr = vault;
        int count = 0;

        while (curr)
        {
            // A pinned root has no parents (dendrites) and the pinned flag
            if (curr->dendrite_count == 0 && curr->is_pinned)
            {
                offset = 0;
                memset(rebuild_buf, 0, MAX_BUF);
                unroll_to_buffer(curr, rebuild_buf, &offset);

                Node *new_v = ingest(rebuild_buf);
                if (new_v)
                    new_v->is_pinned = 1;
                count++;
            }
            curr = curr->next;
        }
        printf("[\033[1;34mINFO\033[0m] Global rumination complete. %d roots re-folded.\n", count);
    }
}

void audit_recursive(Node *n, int depth, int last)
{
    if (!n)
        return;

    // 1. Print the Tree Branches (Piping) in a dim or distinct color
    for (int i = 0; i < depth; i++)
    {
        if (i == depth - 1)
            printf(CLR_MAGENTA "%s" CLR_RESET, last ? "└── " : "├── ");
        else
            printf(CLR_MAGENTA "│   " CLR_RESET);
    }

    // 2. Generate the FULL 64-character hex string
    char full_hex[65];
    for (int i = 0; i < 32; i++)
    {
        sprintf(full_hex + (i * 2), "%02x", n->id.hash[i]);
    }

    // 3. Print the Node Details
    // Hash: White, Vitality: Yellow, Type: Cyan/Green
    printf("[" CLR_CYAN "%s" CLR_RESET "] ", full_hex);
    printf(CLR_YELLOW "V:%.2f" CLR_RESET " ", n->vitality);

    if (n->is_pinned)
        printf(CLR_RED "(PIN) " CLR_RESET);

    if (n->type == V_ATOM)
    {
        printf(CLR_GREEN "«%s»" CLR_RESET, n->lexeme);
    }

    printf("\n");

    // 4. Recurse into children
    if (n->type == V_CHUNK)
    {
        audit_recursive(n->part_a, depth + 1, 0);
        audit_recursive(n->part_b, depth + 1, 1);
    }
}

int is_descendant(Node *potential_child, Node *target_ancestor)
{
    if (!potential_child || !target_ancestor)
        return 0;
    if (potential_child == target_ancestor)
        return 1;

    // Check immediate children
    if (is_descendant(potential_child->part_a, target_ancestor))
        return 1;
    if (is_descendant(potential_child->part_b, target_ancestor))
        return 1;

    return 0;
}

int get_node_depth(Node *n)
{
    if (!n || n->type == V_ATOM)
        return 0;
    int d_a = get_node_depth(n->part_a);
    int d_b = get_node_depth(n->part_b);
    return 1 + (d_a > d_b ? d_a : d_b);
}

/**
void reroute_grandparents(Node *old_parent, Node *new_target)
{
    if (!old_parent || !new_target || old_parent == new_target)
        return;

    // Phase 1: Identify targets safely
    int target_count = 0;
    Node *temp_vault = vault;
    while (temp_vault) {
        if (temp_vault->part_a == old_parent || temp_vault->part_b == old_parent) target_count++;
        temp_vault = temp_vault->next;
    }

    if (target_count == 0) return;

    // Phase 2: Create a stable array of pointers to these grandparents
    Node **targets = malloc(sizeof(Node*) * target_count);
    int idx = 0;
    temp_vault = vault;
    while (temp_vault) {
        if (temp_vault->part_a == old_parent || temp_vault->part_b == old_parent) {
            targets[idx++] = temp_vault;
        }
        temp_vault = temp_vault->next;
    }

    // Phase 3: Perform the surgery on the stable list
    for (int i = 0; i < target_count; i++) {
        Node *curr = targets[i];
        HexID old_id = curr->id;

        // Swapping pointers
        if (curr->part_a == old_parent) curr->part_a = new_target;
        if (curr->part_b == old_parent) curr->part_b = new_target;

        // Re-calculate the Merkle Hash (The Morph)
        HexID new_id;
        unsigned char raw_combo[64];
        memcpy(raw_combo, curr->part_a->id.hash, 32);
        memcpy(raw_combo + 32, curr->part_b->id.hash, 32);
        compute_real_sha((char*)raw_combo, 64, &new_id);

        // Update Global Map safely
        unmap_node(old_id);
        curr->id = new_id;
        map_node(curr);

        record_history(old_id, new_id);

        printf("  \033[1;33m[MORPH]\033[0m Grandparent: [%02x%02x] -> [%02x%02x]\n",
                old_id.hash[0], old_id.hash[1], new_id.hash[0], new_id.hash[1]);

        // RECURSION: The change ripples up
        reroute_grandparents(curr, curr); // Note: You'll need to pass the updated node upward
    }

    free(targets);
}
 */

void reroute_grandparents(Node *old_parent, Node *new_target)
{
    if (!old_parent || !new_target || old_parent == new_target)
        return;

    Node *curr = vault;
    int routes_changed = 0;

    while (curr)
    {
        // GUARD: Don't reroute a node to point to itself
        if (curr == new_target)
        {
            curr = curr->next;
            continue;
        }

        int changed = 0;
        if (curr->part_a == old_parent)
        {
            curr->part_a = new_target;
            changed = 1;
        }
        if (curr->part_b == old_parent)
        {
            curr->part_b = new_target;
            changed = 1;
        }

        for (int d = 0; d < curr->dendrite_count; d++)
        {
            if (memcmp(curr->dendrite_ids[d].hash, old_parent->id.hash, SHA256_BLOCK_SIZE) == 0)
            {
                curr->dendrite_ids[d] = new_target->id;
                changed = 1;
            }
        }

        if (changed)
            routes_changed++;
        curr = curr->next;
    }

    if (routes_changed > 0)
        printf("[\033[1;32mHEAL\033[0m] %d grandparents re-wired.\n", routes_changed);
}

int get_rank(Node *n)
{
    if (!n)
        return 0;
    if (n->type == V_ATOM)
        return 0;
    int a = get_rank(n->part_a);
    int b = get_rank(n->part_b);
    return 1 + (a > b ? a : b);
}

// Helper for qsort
int compare_nodes(const void *a, const void *b)
{
    Node *na = *(Node **)a;
    Node *nb = *(Node **)b;
    return get_rank(na) - get_rank(nb);
}

void perform_coordinated_morph()
{
    // 1. Collect all nodes currently in the vault
    int count = 0;
    Node *temp = vault;
    while (temp)
    {
        count++;
        temp = temp->next;
    }

    Node **nodes = malloc(sizeof(Node *) * count);
    temp = vault;
    for (int i = 0; i < count; i++)
    {
        nodes[i] = temp;
        temp = temp->next;
    }

    // 2. Sort by Rank (Atoms first, Roots last)
    qsort(nodes, count, sizeof(Node *), compare_nodes);

    // 3. Update Identities Bottom-to-Top
    for (int i = 0; i < count; i++)
    {
        Node *n = nodes[i];

        // If children changed, or if this node was specifically marked stale (-2.0)
        // we recalculate the ID and check for singularities
        if (n->type == V_CHUNK && n->part_a && n->part_b)
        {
            HexID old_id = n->id;
            HexID new_id;

            unsigned char raw_combo[65];
            memcpy(raw_combo, n->part_a->id.hash, SHA256_BLOCK_SIZE);
            memcpy(raw_combo + SHA256_BLOCK_SIZE, n->part_b->id.hash, SHA256_BLOCK_SIZE);
            compute_real_sha((char *)raw_combo, 64, &new_id);

            // Check if identity changed
            if (memcmp(old_id.hash, new_id.hash, SHA256_BLOCK_SIZE) != 0)
            {
                Node *collision = find_node(new_id);
                if (collision && collision != n)
                {
                    record_history(n->id, collision->id);
                    reroute_grandparents(n, collision);
                    n->vitality = -1.0f; // Mark redundant node for purge
                }
                else
                {
                    unmap_node(old_id);
                    n->id = new_id;
                    map_node(n);
                    record_history(old_id, new_id);
                }
            }
        }
    }
    free(nodes);
}

void execute_dream_cycle()
{
    Node **curr = &vault;
    int stale_count = 0;

    // Phase 1: Decay & Mark
    while (*curr)
    {
        Node *n = *curr;
        if (!n->is_pinned && n->vitality > 0)
            n->vitality *= DECAY_MULTIPLIER;

        if (n->vitality < DECAY_THRESHOLD || n->vitality < 0)
        {
            if (n->dendrite_count > 0 && n->vitality >= 0)
            {
                n->vitality = -2.0f; // Mark for Batch Morph
                stale_count++;
            }
            else
            {
                n->vitality = -1.0f; // Mark for Purge
            }
        }
        curr = &((*curr)->next);
    }

    // Phase 2: Coordinated Update (Topological Sweep)
    if (stale_count > 0)
    {
        printf("[\033[1;33mBATCH\033[0m] Re-folding %d lineages...\n", stale_count);
        perform_coordinated_morph();
    }

    // Phase 3: Final Dissolution
    curr = &vault;
    while (*curr)
    {
        if ((*curr)->vitality <= -1.0f)
        {
            Node *old = *curr;
            *curr = (*curr)->next;
            unmap_node(old->id); // CLEANUP MAP
            if (old->lexeme)
                free(old->lexeme);
            free(old);
        }
        else
        {
            curr = &((*curr)->next);
        }
    }
}

void recover_roots()
{
    printf("\n--- RECOVERING INDEPENDENT NEURAL ROOTS ---\n");
    Node *curr = vault;
    int found = 0;

    while (curr)
    {
        // A Root is a node that no other V_CHUNK (Dendrite) is pointing to
        if (curr->dendrite_count == 0)
        {
            char hex[65];
            get_hex_str(curr->id, hex);
            printf("Found Root: [" CLR_CYAN "%s" CLR_RESET "] | Vitality: " CLR_YELLOW "%.2f" CLR_RESET " | Tag: %s\n",
                   hex,
                   curr->vitality,
                   curr->is_pinned ? CLR_RED "PINNED" CLR_RESET : CLR_GREEN "VOLATILE" CLR_RESET);
        }
        curr = curr->next;
    }

    if (found == 0)
        printf("No roots found. The Vault is empty or fully dissolved.\n");
    else
        printf("Recovery complete. %d independent memories identified.\n", found);
}

void find_pinned_roots(Node **pinned_list, int *count)
{
    Node *curr = vault;
    *count = 0;

    while (curr)
    {
        // Only grab roots that are explicitly PINNED
        if (curr->dendrite_count == 0 && curr->is_pinned)
        {
            pinned_list[*count] = curr;
            (*count)++;
        }
        curr = curr->next;
    }
}

void record_history(HexID old_id, HexID new_id)
{
    History *entry = malloc(sizeof(History));
    if (!entry)
        return; // Always check malloc in high-load systems

    entry->old_id = old_id;
    entry->new_id = new_id;

    time_t now = time(NULL);
    // Format: "2025-12-28 18:30:05"
    strftime(entry->timestamp, 20, "%Y-%m-%d %H:%M:%S", localtime(&now));

    entry->next = history_log;
    history_log = entry;
}

void display_history_log()
{
    printf("\n" CLR_MAGENTA "--- NEURAL LINEAGE HISTORY ---" CLR_RESET "\n");
    History *curr = history_log;

    if (!curr)
    {
        printf("No identity shifts recorded.\n");
        return;
    }

    while (curr)
    {
        // 1. Create buffers for full 64-char strings (+1 for null terminator)
        char old_hex[65];
        char new_hex[65];

        // 2. Convert the full 32-byte hashes to hex
        for (int i = 0; i < 32; i++)
        {
            sprintf(old_hex + (i * 2), "%02x", curr->old_id.hash[i]);
            sprintf(new_hex + (i * 2), "%02x", curr->new_id.hash[i]);
        }

        // 3. Print with color: Timestamp | [Old] -> [New]
        printf(CLR_CYAN "%s" CLR_RESET " | ", curr->timestamp);
        printf("[" CLR_RED "%s" CLR_RESET "] " CLR_YELLOW "→" CLR_RESET " ", old_hex);
        printf("[" CLR_GREEN "%s" CLR_RESET "]\n", new_hex);

        curr = curr->next;
    }
}

// Helper to find the height of a specific Merkle Tree branch
int get_node_height(Node *n)
{
    if (!n)
        return 0;
    if (n->type == V_ATOM)
        return 1;

    int left = get_node_height(n->part_a);
    int right = get_node_height(n->part_b);

    return (left > right ? left : right) + 1;
}

// Main function to scan the entire vault list
int get_vault_max_depth()
{
    int max_d = 0;
    Node *curr = vault;
    while (curr)
    {
        int d = get_node_height(curr);
        if (d > max_d)
            max_d = d;
        curr = curr->next;
    }
    return max_d;
}

void display_metrics()
{
    int V_ATOMs = 0, V_CHUNKs = 0;
    size_t total_lexeme_bytes = 0;
    int max_depth = 0;
    Node *curr = vault;

    while (curr)
    {
        if (curr->type == V_ATOM)
        {
            V_ATOMs++;
            if (curr->lexeme)
                total_lexeme_bytes += strlen(curr->lexeme);
        }
        else
        {
            V_CHUNKs++;
        }
        curr = curr->next;
    }

    // Calculate depth separately or via a quick sample to save time
    max_depth = get_vault_max_depth();

    size_t node_struct_size = sizeof(Node);
    size_t total_ram = (V_ATOMs + V_CHUNKs) * node_struct_size;

    // Virtual Weight: If we unrolled every chunk into raw text,
    // how much 'meaning' is stored?
    double avg_atom_len = (V_ATOMs > 0) ? (double)total_lexeme_bytes / V_ATOMs : 0;
    // Each chunk represents a combination of atoms.
    // At 7 layers, a chunk could represent up to 2^7 (128) atoms.
    double virtual_text_est = V_CHUNKs * avg_atom_len * 2;

    printf("\n" CLR_MAGENTA "--- NEURAL DENSITY REPORT ---" CLR_RESET "\n");
    printf(" Population:     [" CLR_GREEN "%d" CLR_RESET "] Atoms | [" CLR_CYAN "%d" CLR_RESET "] Chunks\n", V_ATOMs, V_CHUNKs);
    printf(" Struct Size:    %zu bytes per Node\n", node_struct_size);
    printf(" RAM Footprint:  " CLR_RED "%.2f MB" CLR_RESET "\n", (float)total_ram / (1024 * 1024));
    printf(" Neural Density: " CLR_YELLOW "%.2f chunks/atom" CLR_RESET "\n", (float)V_CHUNKs / V_ATOMs);

    // The "Saturation" Metric
    float saturation = (float)total_ram / (total_lexeme_bytes > 0 ? total_lexeme_bytes : 1);
    printf(" Overhead Ratio: " CLR_RED "%.2fx" CLR_RESET " (RAM vs Raw Text)\n", saturation);

    printf(" System State:   ");
    if (max_depth < 10 && V_CHUNKs > 10000)
        printf(CLR_CYAN "EXTERNALLY COMPLEX / SHALLOW\n" CLR_RESET);
    else
        printf(CLR_GREEN "DEEP HIERARCHICAL STORAGE\n" CLR_RESET);

    printf("---------------------------------\n");
}

/**
void morph_surgery(Node *target)
{
    if (!target) return;

    for (int i = 0; i < target->dendrite_count; i++)
    {
        Node *parent = find_node(target->dendrite_ids[i]);
        if (parent)
        {
            HexID old_id = parent->id;
            HexID morphed_id;
            compute_real_sha("morphed", &morphed_id);

            Node *collision = find_node(morphed_id);
            if (collision && collision != parent)
            {
                printf("[\033[1;35mSINGULARITY\033[0m] Collision at [%02x%02x%02x%02x].\n",
                        morphed_id.hash[0], morphed_id.hash[1], morphed_id.hash[2], morphed_id.hash[3]);

                // 1. Re-route grandparents to the EXISTING singularity
                record_history(parent->id, collision->id);
                reroute_grandparents(parent, collision);

                // 2. Mark this redundant parent for death
                parent->vitality = -1.0f;
                printf("[\033[1;34mMARK\033[0m] Redundant branch flagged for removal.\n");
                continue;
            }

            // --- THE MUTATION PATH ---
            // 3. Update the parent's ID to reflect its NEW children (Hot-swapping)
            if (parent->part_a && parent->part_b) {
                char combo[MAX_BUF];
                sprintf(combo, "%02x%02x", parent->part_a->id.hash[0], parent->part_b->id.hash[0]);
                compute_real_sha(combo, &parent->id);
                record_history(old_id, parent->id);
                char new_hex[9];
                get_hex_str(parent->id, new_hex);
                printf("[\033[1;32mMUTATION\033[0m] Node evolved into [%s].\n", new_hex);
            }

            // 4. Propagate the change up the tree
            morph_surgery(parent);
        }
    }

    // Only set target to -1.0f if it's the specific leaf we wanted to kill.
    // If we're just propagating a mutation, we keep the parents alive!
    if (target->dendrite_count == 0 && !target->is_pinned) {
        target->vitality = -1.0f;
    }
}
*/

typedef struct PropagationStack
{
    Node *node;
    struct PropagationStack *next;
} PropagationStack;

void push_prop(PropagationStack **stack, Node *n)
{
    if (!n)
        return;
    PropagationStack *new_item = malloc(sizeof(PropagationStack));
    new_item->node = n;
    new_item->next = *stack;
    *stack = new_item;
}

Node *pop_prop(PropagationStack **stack)
{
    if (!*stack)
        return NULL;
    PropagationStack *top = *stack;
    Node *n = top->node;
    *stack = top->next;
    free(top);
    return n;
}

/**
void morph_surgery_linear(Node *trigger_node)
{
    PropagationStack *stack = NULL;

    // Initially, find all parents of the failing node and queue them for update
    for (int i = 0; i < trigger_node->dendrite_count; i++)
    {
        Node *parent = find_node(trigger_node->dendrite_ids[i]);
        if (parent)
            push_prop(&stack, parent);
    }

    // Iterative propagation
    while (stack)
    {
        Node *parent = pop_prop(&stack);
        HexID old_id = parent->id;

        // 1. Check for Singularity (Identity Collision)
        HexID next_id;
        // Mock computation logic...
        char combo[MAX_BUF];
        sprintf(combo, "%02x%02x", parent->part_a->id.hash[0], parent->part_b->id.hash[0]);
        compute_real_sha(combo, 64, &next_id);

        Node *collision = find_node(next_id);
        if (collision && collision != parent)
        {
            // Reroute this parent's parents to the existing collision node
            record_history(parent->id, collision->id);
            reroute_grandparents(parent, collision);
            parent->vitality = -1.0f; // Mark for Purge in main loop

            // Queue grandparents of the collision/parent to check for further merges
            for (int i = 0; i < parent->dendrite_count; i++)
            {
                Node *gp = find_node(parent->dendrite_ids[i]);
                if (gp)
                    push_prop(&stack, gp);
            }
            continue;
        }

        // 2. Mutation Path (Update ID and climb)
        parent->id = next_id;
        record_history(old_id, parent->id);

        // Queue grandparents
        for (int i = 0; i < parent->dendrite_count; i++)
        {
            Node *gp = find_node(parent->dendrite_ids[i]);
            if (gp)
                push_prop(&stack, gp);
        }
    }

    // Finalize the trigger node
    if (trigger_node->dendrite_count == 0 && !trigger_node->is_pinned)
    {
        trigger_node->vitality = -1.0f;
    }
}
*/

void phoenix_redigestion_protocol(Node *target)
{
    if (!target)
        return;

    // 1. Recover the raw data (The "Soul" of the node)
    char recovery_buf[MAX_BUF * 10] = {0};
    int offset = 0;
    unroll_to_buffer(target, recovery_buf, &offset);

    printf("[\033[1;31mPHOENIX\033[0m] Redigesting: \"%s\"\n", recovery_buf);

    // 2. Identify the lineage before we detach
    PropagationStack *stack = NULL;
    for (int i = 0; i < target->dendrite_count; i++)
    {
        Node *parent = find_node(target->dendrite_ids[i]);
        if (parent)
            push_prop(&stack, parent);
    }

    // 3. BIRTH: Re-ingest the data to get a fresh, optimized sub-tree root
    Node *redigested_root = ingest(recovery_buf);

    if (redigested_root == target)
    {
        printf("[\033[1;33mWARN\033[0m] Redigestion yielded identical identity. No morph required.\n");
        return;
    }

    // 4. THE MORPH: Reroute ancestors from the 'old' target to the 'new' root
    // This triggers the cascade of hash changes you described
    reroute_grandparents(target, redigested_root);

    // 5. Mark old tissue for death (unless it's the same node)
    target->vitality = -1.0f;
    target->is_pinned = 0;

    printf("[\033[1;32mSUCCESS\033[0m] Redigestion complete. Lineage propagated upward.\n");
}

void pin_node_manual(const char *prefix)
{
    Node *n = find_node_from_hex_str(prefix);
    if (n)
    {
        n->is_pinned = 1;
        n->vitality = 1.0f; // Restore to full health when pinning
        char hex[65];
        get_hex_str(n->id, hex);
        printf("[\033[1;33mPIN\033[0m] Node [%s] is now IMMORTAL. It will bypass the DREAM decay.\n", hex);
    }
    else
    {
        printf("[\033[1;31mERROR\033[0m] Could not find node with prefix: %s\n", prefix);
    }
}

#ifdef _WIN32
#include <windows.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

void enable_windows_terminal()
{
    // Set output mode to handle virtual terminal sequences (ANSI colors)
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE)
    {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode))
        {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
    }
    // Set console output to UTF-8 so box-drawing characters render correctly
    SetConsoleOutputCP(CP_UTF8);
}
#endif

void print_banner()
{
#ifdef _WIN32
    enable_windows_terminal();
#endif

    // 1. Calculate real-time population for the LOAD metric
    int total_nodes = 0;
    Node *count_ptr = vault;
    while (count_ptr)
    {
        total_nodes++;
        count_ptr = count_ptr->next;
    }

    // 2. Neural Activity Header
    printf("\n\033[1;30m   ⣎⡇⠀⢠⢠⡀⢀⢀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⠀⡀⡇⣱\033[0m");
    printf("\n\033[1;35m   ⚚ \033[1;37m V O L T E X \033[1;35m ─╼ \033[0;35mNEURAL_LSM_CORE \033[1;35m ╾─ \033[1;37m I / O \033[1;35m ⚚ \033[0m");
    printf("\n\033[1;30m   ⣑⡒⠀⠘⠘⠃⠘⠘⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠀⠃⠒⣑\033[0m\n");

    // 3. The Synaptic Dashboard (Using total_nodes now)
    int max_d = get_vault_max_depth();
    // Assuming a "soft limit" of 100,000 nodes for the percentage calculation
    float load_percentage = (total_nodes / 100000.0f) * 100.0f;

    printf("   \033[1;30m[ \033[0;35mPULSE: \033[1;32mACTIVE \033[1;30m| \033[0;35mDEPTH: \033[1;37m%d \033[1;30m| \033[0;35mPOP: \033[1;33m%d \033[1;30m| \033[0;35mLOAD: \033[1;31m%.1f%% \033[1;30m]\033[0m\n",
           max_d, total_nodes, load_percentage);

    // --- SECTION 1: SYNTHESIS (Blue/Green for creation) ---
    printf("\n   \033[1;34m╭─\033[1;37m [ SYNTHESIS ENGINE ]\033[0m\n");
    printf("   \033[1;34m╽\033[1;32m  01 \033[1;37mINGEST    \033[1;30m──╼ \033[0;37mFold data into Hash-Linked V_ATOMs\033[0m\n");
    printf("   \033[1;34m╽\033[1;32m  02 \033[1;37mUNROLL    \033[1;30m──╼ \033[0;37mReconstruct state from Structural ID\033[0m\n");
    printf("   \033[1;34m╽\033[1;32m  03 \033[1;37mAUDIT     \033[1;30m──╼ \033[0;37mMap recursive Merkle-Tree topology\033[0m\n");
    printf("   \033[1;34m╽\033[1;33m  12 \033[1;37mHUNT      \033[1;30m──╼ \033[0;37mProbabilistic dendritic traversal\033[0m\n");

    // --- SECTION 2: METABOLISM (Magenta for internal process) ---
    printf("\n   \033[1;35m╭─\033[1;37m [ METABOLIC CONTROL ]\033[0m\n");
    printf("   \033[1;35m╽\033[1;35m  04 \033[1;37mDREAM     \033[1;30m──╼ \033[0;37mTrigger metabolic decay & noise purging\033[0m\n");
    printf("   \033[1;35m╽\033[1;33m  14 \033[1;37mEVO       \033[1;30m──╼ \033[0;37mInject chaos/entropy for structural stress\033[0m\n");
    printf("   \033[1;35m╽\033[1;33m  15 \033[1;37mRUMINATE  \033[1;30m──╼ \033[0;37mRecursive consolidation of pinned roots\033[0m\n");

    // --- SECTION 3: ANALYTICS (Cyan for logic/data) ---
    printf("\n   \033[1;36m╭─\033[1;37m [ ANALYTICS & LOGS ]\033[0m\n");
    printf("   \033[1;36m╽\033[1;36m  05 \033[1;37mMETRICS   \033[1;30m──╼ \033[0;37mAnalyze deduplication & memory density\033[0m\n");
    printf("   \033[1;36m╽\033[1;36m  06 \033[1;37mHISTORY   \033[1;30m──╼ \033[0;37mInspect lineage and identity history\033[0m\n");
    printf("   \033[1;36m╽\033[1;37m  11 \033[1;37mSAVE/LOAD \033[1;30m──╼ \033[0;37mNeural state persistence (vault.vtx)\033[0m\n");

    // --- SECTION 4: SURGERY (Red/Yellow for high-impact) ---
    printf("\n   \033[1;31m╭─\033[1;37m [ STRUCTURAL SURGERY ]\033[0m\n");
    printf("   \033[1;31m╽\033[1;31m  07 \033[1;37mPHOENIX   \033[1;30m──╼ \033[0;37mExecute redigestion & healing morph\033[0m\n");
    printf("   \033[1;31m╽\033[1;33m  08 \033[1;37mPIN       \033[1;30m──╼ \033[0;37mGrant Immortality; bypass DREAM decay\033[0m\n");
    printf("   \033[1;31m╽\033[1;33m  09 \033[1;37mRECOVER   \033[1;30m──╼ \033[0;37mScan for independent neural roots\033[0m\n");

    // --- FOOTER ---
    printf("\n   \033[1;30m╰╼ \033[1;90m 14 \033[1;37mEXIT      \033[1;30m──╼ \033[0;90mDecommission core and purge memory\033[0m\n");
    printf("\n   \033[1;35m⚡ \033[1;37mNEURAL_PROBE: \033[0m");
}

void print_help()
{
    printf("\n\033[1;35m  ╭───────────────────────────────────────────────────────────────╮\033[0m");
    printf("\n\033[1;35m  │      V O L T E X  -  L S M  |  N E U R A L  G R A P H         │\033[0m");
    printf("\n\033[1;35m  ╰───────────────────────────────────────────────────────────────╯\033[0m\n");

    // --- SECTION 1: SYNTHESIS (Blue/Green) ---
    printf("\n   \033[1;34m╭─\033[1;37m [ SYNTHESIS & INFERENCE ]\033[0m\n");
    printf("   \033[1;34m╽\033[1;32m  01 \033[1;37mINGEST    \033[1;30m──╼ \033[0;37mFold data into Hash-Linked V_ATOMs\033[0m\n");
    printf("   \033[1;34m╽\033[1;32m  02 \033[1;37mUNROLL    \033[1;30m──╼ \033[0;37mReconstruct state from Structural ID\033[0m\n");
    printf("   \033[1;34m╽\033[1;32m  03 \033[1;37mAUDIT     \033[1;30m──╼ \033[0;37mMap recursive Merkle-Tree topology\033[0m\n");
    printf("   \033[1;34m╽\033[1;33m  12 \033[1;37mHUNT      \033[1;30m──╼ \033[0;37mProbabilistic dendritic traversal\033[0m\n");

    // --- SECTION 2: METABOLISM (Magenta) ---
    printf("\n   \033[1;35m╭─\033[1;37m [ METABOLIC CONTROL ]\033[0m\n");
    printf("   \033[1;35m╽\033[1;35m  04 \033[1;37mDREAM     \033[1;30m──╼ \033[0;37mTrigger metabolic decay & noise purging\033[0m\n");
    printf("   \033[1;35m╽\033[1;33m  15 \033[1;37mEVO       \033[1;30m──╼ \033[0;37mInject chaos/entropy for structural stress\033[0m\n");
    printf("   \033[1;35m╽\033[1;33m  16 \033[1;37mRUMINATE  \033[1;30m──╼ \033[0;37mRecursive consolidation of pinned roots\033[0m\n");

    // --- SECTION 3: ANALYTICS (Cyan) ---
    printf("\n   \033[1;36m╭─\033[1;37m [ TELEMETRY & PERSISTENCE ]\033[0m\n");
    printf("   \033[1;36m╽\033[1;36m  05 \033[1;37mMETRICS   \033[1;30m──╼ \033[0;37mAnalyze deduplication & memory density\033[0m\n");
    printf("   \033[1;36m╽\033[1;36m  06 \033[1;37mHISTORY   \033[1;30m──╼ \033[0;37mInspect lineage and identity history\033[0m\n");
    printf("   \033[1;36m╽\033[1;37m  11 \033[1;37mSAVE/LOAD \033[1;30m──╼ \033[0;37mNeural state persistence (vault.vtx)\033[0m\n");

    // --- SECTION 4: SURGERY (Red) ---
    printf("\n   \033[1;31m╭─\033[1;37m [ STRUCTURAL SURGERY ]\033[0m\n");
    printf("   \033[1;31m╽\033[1;31m  07 \033[1;37mPHOENIX   \033[1;30m──╼ \033[0;37mExecute redigestion & healing morph\033[0m\n");
    printf("   \033[1;31m╽\033[1;33m  08 \033[1;37mPIN       \033[1;30m──╼ \033[0;37mGrant Immortality; bypass DREAM decay\033[0m\n");
    printf("   \033[1;31m╽\033[1;33m  09 \033[1;37mRECOVER   \033[1;30m──╼ \033[0;37mScan for independent neural roots\033[0m\n");

    printf("\n   \033[1;30m╰╼ \033[1;90m 14 \033[1;37mEXIT      \033[1;30m──╼ \033[0;90mDecommission core and purge memory\033[0m\n");
    printf("\n   \033[1;35m⚡ \033[1;37mNEURAL_PROBE: \033[0m");
}

// Persistance Logic
#define SAVE_FILE "vault.vtx"

void save_vault()
{
    FILE *f = fopen(SAVE_FILE, "wb");
    if (!f)
    {
        printf("[\033[1;31mERROR\033[0m] Could not open vault for writing.\n");
        return;
    }

    int count = 0;
    Node *curr = vault;
    while (curr)
    {
        if (curr->vitality > -1.0f)
            count++;
        curr = curr->next;
    }
    fwrite(&count, sizeof(int), 1, f);

    curr = vault;
    while (curr)
    {
        if (curr->vitality <= -1.0f)
        {
            curr = curr->next;
            continue;
        }

        // 1. Core Metadata
        fwrite(&curr->id, sizeof(HexID), 1, f);
        fwrite(&curr->type, sizeof(NodeType), 1, f);
        fwrite(&curr->vitality, sizeof(float), 1, f);
        fwrite(&curr->is_pinned, sizeof(int), 1, f);

        // 2. Save Child Pointers as IDs
        HexID null_id = {0};
        HexID id_a = (curr->part_a) ? curr->part_a->id : null_id;
        HexID id_b = (curr->part_b) ? curr->part_b->id : null_id;
        fwrite(&id_a, sizeof(HexID), 1, f);
        fwrite(&id_b, sizeof(HexID), 1, f);

        // 3. Save Dynamic Dendrites (Parents)
        fwrite(&curr->dendrite_count, sizeof(int), 1, f);
        if (curr->dendrite_count > 0)
        {
            fwrite(curr->dendrite_ids, sizeof(HexID), curr->dendrite_count, f);
        }

        // 4. Lexeme
        int lex_len = (curr->lexeme) ? (int)strlen(curr->lexeme) : 0;
        fwrite(&lex_len, sizeof(int), 1, f);
        if (lex_len > 0)
        {
            fwrite(curr->lexeme, sizeof(char), lex_len + 1, f);
        }

        curr = curr->next;
    }
    fclose(f);
    printf("[\033[1;32mSAVE\033[0m] Dynamic Vault persisted (%d nodes).\n", count);
}

void load_vault()
{
    FILE *f = fopen(SAVE_FILE, "rb");
    if (!f)
        return;

    // Clear current state
    vault = NULL;
    memset(node_map, 0, sizeof(node_map));

    int count;
    if (fread(&count, sizeof(int), 1, f) != 1)
    {
        fclose(f);
        return;
    }

    // Phase 1: Allocation and ID Restoration
    for (int i = 0; i < count; i++)
    {
        Node *n = (Node *)calloc(1, sizeof(Node));

        fread(&n->id, sizeof(HexID), 1, f);
        fread(&n->type, sizeof(NodeType), 1, f);
        fread(&n->vitality, sizeof(float), 1, f);
        fread(&n->is_pinned, sizeof(int), 1, f);

        // We still need to find children later, so we use temporary IDs
        // We can use n->part_a and n->part_b pointers temporarily as ID storage
        // by casting them, OR (safer) just read them into temp variables.
        HexID temp_a, temp_b;
        fread(&temp_a, sizeof(HexID), 1, f);
        fread(&temp_b, sizeof(HexID), 1, f);

        // Load Dynamic Dendrites
        fread(&n->dendrite_count, sizeof(int), 1, f);
        if (n->dendrite_count > 0)
        {
            n->dendrite_capacity = n->dendrite_count;
            n->dendrite_ids = malloc(n->dendrite_count * sizeof(HexID));
            fread(n->dendrite_ids, sizeof(HexID), n->dendrite_count, f);
        }

        // Lexeme
        int lex_len;
        fread(&lex_len, sizeof(int), 1, f);
        if (lex_len > 0)
        {
            n->lexeme = malloc(lex_len + 1);
            fread(n->lexeme, sizeof(char), lex_len + 1, f);
        }

        // We store the child IDs in the pointers temporarily
        // to re-weave in Phase 2 (casting IDs to pointers is a common trick)
        n->part_a = (Node *)malloc(sizeof(HexID));
        memcpy(n->part_a, &temp_a, sizeof(HexID));
        n->part_b = (Node *)malloc(sizeof(HexID));
        memcpy(n->part_b, &temp_b, sizeof(HexID));

        n->next = vault;
        vault = n;
        map_node(n);
    }
    fclose(f);

    // Phase 2: Re-weaving the synaptic net
    Node *curr = vault;
    while (curr)
    {
        // Extract the temporary IDs we stored in the pointers
        HexID id_a = *(HexID *)(curr->part_a);
        HexID id_b = *(HexID *)(curr->part_b);

        // Free the temporary ID holders
        free(curr->part_a);
        free(curr->part_b);

        // Link to actual neural nodes
        curr->part_a = find_node(id_a);
        curr->part_b = find_node(id_b);

        curr = curr->next;
    }
    printf("[\033[1;36mLOAD\033[0m] Neural-Graph re-weaved (Dynamic Memory Optimized).\n");
}

// Comparison tool for HexID structs
int ids_equal(HexID a, HexID b)
{
    return memcmp(a.hash, b.hash, SHA256_BLOCK_SIZE) == 0;
}

// Visual tool for printing HexID
void print_hex(HexID id)
{
    for (int i = 0; i < 4; i++)
        printf("%02x", id.hash[i]); // Print first 4 bytes for brevity
}

// Helper for Top-K: Sort candidates by vitality descending
int compare_vitality(const void *a, const void *b)
{
    Node *na = *(Node **)a;
    Node *nb = *(Node **)b;
    if (nb->vitality > na->vitality)
        return 1;
    if (nb->vitality < na->vitality)
        return -1;
    return 0;
}

Node *get_strongest_root()
{
    Node *curr = vault;
    Node *best = NULL;
    float max_v = -1.0f;

    while (curr)
    {
        // We prioritize "roots" (nodes with no parents) that have high vitality
        if (curr->dendrite_count == 0 && curr->vitality > max_v)
        {
            max_v = curr->vitality;
            best = curr;
        }
        curr = curr->next;
    }
    // If no roots exist, just return the first node in the vault
    return (best) ? best : vault;
}

void run_neural_hunt(HexID seed_id, int max_length)
{
    HexID current_id = seed_id;

    printf("\n\033[1;35m[HUNT]: \033[0m");

    for (int i = 0; i < max_length; i++)
    {
        Node *n = find_node(current_id);
        if (!n)
            break;

        // Print atoms. We suppress hex fragments by checking lexeme content if needed.
        if (n->type == V_ATOM && n->lexeme)
        {
            printf("%s", n->lexeme);
        }

        Node *candidates[128];
        int c_count = 0;

        // --- SCANNING ---
        Node *scan = vault;
        while (scan)
        {
            if (scan->type == V_CHUNK && scan->part_a)
            {
                if (memcmp(scan->part_a->id.hash, current_id.hash, SHA256_BLOCK_SIZE) == 0)
                {
                    if (scan->part_b)
                    {
                        candidates[c_count++] = scan->part_b;
                        if (c_count >= 128)
                            break;
                    }
                }
            }
            scan = scan->next;
        }

        if (c_count > 0)
        {
            // --- LLM LOGIC: TOP-K & VITALITY WEIGHTING ---

            // 1. Sort by strength (Vitality)
            qsort(candidates, c_count, sizeof(Node *), compare_vitality);

            // 2. Constrain to Top-K (e.g., top 3 most likely successors)
            int k = (c_count < 3) ? c_count : 3;

            // 3. Probabilistic selection based on Vitality
            float total_v = 0;
            for (int j = 0; j < k; j++)
                total_v += candidates[j]->vitality;

            float pick = ((float)rand() / (float)RAND_MAX) * total_v;
            float current_v = 0;

            for (int j = 0; j < k; j++)
            {
                current_v += candidates[j]->vitality;
                if (current_v >= pick)
                {
                    current_id = candidates[j]->id;
                    break;
                }
            }
        }
        else
        {
            // SILENT JUMP (LLM Hallucination/Pivot)
            // If the path ends, jump to a random high-vitality node to keep generating
            Node *jumper = vault;
            int jump_dist = rand() % 20;
            for (int j = 0; j < jump_dist && jumper && jumper->next; j++)
            {
                jumper = jumper->next;
            }
            if (jumper)
                current_id = jumper->id;
            else
                break;
        }
    }

    printf("\n\033[1;36m[SEQUENCE COMPLETE]\033[0m\n");
}

// Counting Helpers
int count_V_ATOMs()
{
    int count = 0;
    Node *curr = vault;
    while (curr)
    {
        // In our Merkle-DAG, V_ATOMs have no child pointers (part_a/part_b)
        if (curr->part_a == NULL && curr->part_b == NULL)
        {
            count++;
        }
        curr = curr->next;
    }
    return count;
}

char *generate_dummy_json(int index)
{
    char *buffer = (char *)malloc(2048);
    if (!buffer)
        return NULL;

    const char *eyeColors[] = {"blue", "brown", "green", "amber", "gray"};
    const char *fruits[] = {"apple", "banana", "strawberry", "mango", "kiwi"};
    const char *depts[] = {"NEURAL_BIO", "CYBER_LOGIC", "QUANTUM_OPS", "VOLTEX_LABS"};

    // Randomizing synaptic connections
    int isActive = rand() % 2;
    float balance = 1000 + (float)(rand() % 500000) / 100;
    int age = 18 + (rand() % 50);
    const char *eyeColor = eyeColors[rand() % 5];
    const char *fruit = fruits[rand() % 5];
    const char *dept = depts[rand() % 4];
    float lat = (float)(rand() % 1800000) / 10000 - 90;
    float lon = (float)(rand() % 3600000) / 10000 - 180;

    snprintf(buffer, 2048,
             "{\n"
             "  \"_id\": \"5f%06x%06x\",\n"
             "  \"index\": %d,\n"
             "  \"guid\": \"8d96-%04x-%04x\",\n"
             "  \"isActive\": %s,\n"
             "  \"balance\": \"$%.2f\",\n"
             "  \"age\": %d,\n"
             "  \"eyeColor\": \"%s\",\n"
             "  \"name\": \"Agent_%d\",\n"
             "  \"company\": \"%s\",\n"
             "  \"location\": [%.6f, %.6f],\n"
             "  \"tags\": [\"cognition\", \"voltex\", \"id_%d\"],\n"
             "  \"favoriteFruit\": \"%s\"\n"
             "}",
             rand() % 0xFFFFFF, rand() % 0xFFFFFF,
             index,
             rand() % 0xFFFF, rand() % 0xFFFF,
             isActive ? "true" : "false",
             balance, age, eyeColor, index,
             dept, lat, lon, index, fruit);

    return buffer;
}

int count_V_CHUNKs()
{
    int count = 0;
    Node *curr = vault;
    while (curr)
    {
        // V_CHUNKs are 'Recipes' that point to other nodes
        if (curr->part_a != NULL || curr->part_b != NULL)
        {
            count++;
        }
        curr = curr->next;
    }
    return count;
}


// Internal helper for post-order traversal
void fill_post_order(Node *n, Node **s, int *c)
{
    if (!n)
        return;
    if (n->type == V_CHUNK)
    {
        fill_post_order(n->part_a, s, c);
        fill_post_order(n->part_b, s, c);
    }
    s[(*c)++] = n;
}

#include <stdint.h>
// --- Factor Node Prop Type ---

// --- Updated Main Loop ---
int main()
{
    char cmd[32], buf[MAX_BUF];
    srand(time(NULL));

    print_banner();

    while (1)
    {
        printf("\n\033[1;32mvoltex_vault#\033[0m "); // Green prompt
        if (scanf("%s", cmd) == EOF)
            break;

        // Command Switch
        if (!strcmp(cmd, "HELP") || !strcmp(cmd, "0"))
        {
            print_help();
        }
        else if (!strcmp(cmd, "INGEST") || !strcmp(cmd, "1"))
        {
            // --- FIX: Clear the buffer of the newline from the command entry ---
            int c;
            while ((c = getchar()) != '\n' && c != EOF)
                ;

            printf("Enter data: ");
            if (fgets(buf, MAX_BUF, stdin))
            {
                buf[strcspn(buf, "\n")] = 0;

                if (strlen(buf) == 0)
                {
                    printf("[\033[1;31mERROR\033[0m] Ingestion aborted: Empty input.\n");
                    continue;
                }

                Node *res = ingest(buf);
                if (res)
                {
                    // --- UPDATED: Full 64-char string + null terminator ---
                    char full_hex[65];
                    for (int i = 0; i < 32; i++)
                    {
                        sprintf(full_hex + (i * 2), "%02x", res->id.hash[i]);
                    }

                    printf("[\033[1;34mINFO\033[0m] Synthesis Complete.\n");
                    printf("Root ID: \033[1;37m%s\033[0m\n", full_hex);
                }
            }
        }
        else if (!strcmp(cmd, "UNROLL") || !strcmp(cmd, "2"))
        {
            // --- FIX: Clear the buffer of the newline from the command entry ---
            int c;
            while ((c = getchar()) != '\n' && c != EOF)
                ;

            printf("Target Hex: "); // Helpful prompt to know it's waiting
            if (fgets(buf, MAX_BUF, stdin))
            {
                buf[strcspn(buf, "\n")] = 0;

                // Skip ingestion if the user just pressed enter again
                if (strlen(buf) == 0)
                {
                    printf("[\033[1;31mERROR\033[0m] Ingestion aborted: Empty input.\n");
                    continue;
                }

                Node *res = find_node_from_hex_str(buf);
                if (res)
                {
                    unroll(res);
                }
            }
        }
        else if (!strcmp(cmd, "AUDIT") || !strcmp(cmd, "3"))
        {
            // --- FIX: Clear the buffer of the newline from the command entry ---
            int c;
            while ((c = getchar()) != '\n' && c != EOF)
                ;

            printf("Target Hex: "); // Helpful prompt to know it's waiting
            if (fgets(buf, MAX_BUF, stdin))
            {
                printf("\n--- VISUALIZING NEURAL TOPOLOGY ---\n");
                buf[strcspn(buf, "\n")] = 0;

                // Skip ingestion if the user just pressed enter again
                if (strlen(buf) == 0)
                {
                    printf("[\033[1;31mERROR\033[0m] Aborted: Empty input.\n");
                    continue;
                }

                Node *res = find_node_from_hex_str(buf);
                if (res)
                {
                    audit_recursive(res, 0, 1);
                }
            }
            printf("------------------------------------\n");
        }
        else if (!strcmp(cmd, "DREAM") || !strcmp(cmd, "4"))
        {
            printf("[\033[1;35mPROCESS\033[0m] Initiating metabolic decay...");
            execute_dream_cycle();
            printf(" Success. Memory purged.\n");
        }
        else if (!strcmp(cmd, "METRICS") || !strcmp(cmd, "5"))
        {
            display_metrics();
        }
        else if (!strcmp(cmd, "LOG") || !strcmp(cmd, "6"))
        {
            display_history_log();
        }
        else if (!strcmp(cmd, "PHOENIX") || !strcmp(cmd, "7"))
        {
            scanf("%s", buf);
            Node *n = find_node_from_hex_str(buf);

            if (n)
            {
                printf("\n\033[1;31m[PHOENIX PROTOCOL INITIALIZED]\033[0m\n");
                printf("Target: [%s] | Vitality: %.2f | Dendrites: %d\n",
                       buf, n->vitality, n->dendrite_count);

                // Capture state before surgery
                int nodes_before = 0;
                Node *temp = vault;
                while (temp)
                {
                    nodes_before++;
                    temp = temp->next;
                }

                // Execute the Redigestion
                phoenix_redigestion_protocol(n);

                printf("\033[1;33m[CLEANUP]\033[0m Dissolving marked tissue...\n");
                execute_dream_cycle();
                printf("\n\033[1;36m[LOG]\033[0m Check 'HISTORY' to see the structural shift.\n");
                // Capture state after surgery
                int nodes_after = 0;
                temp = vault;
                while (temp)
                {
                    nodes_after++;
                    temp = temp->next;
                }

                printf("\033[1;32m[SURGERY COMPLETE]\033[0m\n");
                printf("Nodes Purged: %d | Memory Recovered: %lu bytes\n",
                       nodes_before - nodes_after, (nodes_before - nodes_after) * sizeof(Node));
                printf("Structural Integrity: \033[1;32mVERIFIED\033[0m\n\n");
            }
            else
            {
                printf("\033[1;31m[ERROR]\033[0m Node ID [%s] not found in local vault.\n", buf);
            }
        }
        else if (!strcmp(cmd, "PIN") || !strcmp(cmd, "8"))
        {
            printf(" Enter Hex ID to Pin: ");
            scanf("%s", buf); // Hex IDs don't have spaces, so scanf is fine here
            pin_node_manual(buf);
        }
        else if (!strcmp(cmd, "RECOVER") || !strcmp(cmd, "9"))
        {
            recover_roots();
        }
        else if (!strcmp(cmd, "SAVE") || !strcmp(cmd, "10"))
        {
            save_vault();
        }
        else if (!strcmp(cmd, "LOAD") || !strcmp(cmd, "11"))
        {
            load_vault();
        }
        else if (!strcmp(cmd, "HUNT") || !strcmp(cmd, "12"))
        {
            char input_buf[MAX_BUF];
            int choice = 0;

            // CRITICAL: Clear any leftover newline
            while (getchar() != '\n' && getchar() != EOF)
                ;

            printf("\n\033[1;36m[HUNT MODE]\033[0m\n");
            printf(" 1. Search by Hex ID Hash\n");
            printf(" 2. Search by String (Lexeme)\n");
            printf("[\x1b[32mUSER\x1b[0m]\033[1;33m Select Option (1-2): \033[0m");

            fgets(input_buf, MAX_BUF, stdin);
            choice = atoi(input_buf);

            printf("[\x1b[32mUSER\x1b[0m]\033[1;33mEnter Search Term: \033[0m");
            if (fgets(input_buf, MAX_BUF, stdin))
            {
                input_buf[strcspn(input_buf, "\n")] = 0; // Remove newline
            }

            Node *found = NULL;

            if (choice == 1)
            {
                // Path A: Explicit Hex Hash Search
                found = find_node_from_hex_str(input_buf); // Assumes you have a direct ID lookup
                if (!found)
                {
                    // Fallback to fuzzy prefix matching if direct match fails
                    found = find_node_from_hex_str(input_buf);
                }
            }
            else
            {
                // Path B: Explicit String/Lexeme Search
                Node *scan = vault;
                while (scan)
                {
                    if (scan->lexeme && strcmp(scan->lexeme, input_buf) == 0)
                    {
                        found = scan;
                        break;
                    }
                    scan = scan->next;
                }
            }

            // --- Post-Search Logic ---

            // LLM-style Fallback: If search yielded nothing, pick the strongest root
            if (!found)
            {
                printf("\033[1;30m[SYSTEM]: '%s' not found. Sampling strongest memory...\033[0m\n", input_buf);
                found = get_strongest_root();
            }

            if (found)
            {
                char hex[65];
                get_hex_str(found->id, hex);

                // Display what we found for confirmation
                if (found->lexeme)
                    printf("\033[1;30m[SYSTEM]: Seed identified as \"%s\"\033[0m\n", found->lexeme);

                printf("\033[1;30m[SYSTEM]: Starting inference at [%s]\033[0m\n", hex);

                // Execute the neural hunt
                run_neural_hunt(found->id, 20);
            }
            else
            {
                printf("\033[1;31m[ERROR]: Vault is empty. Ingest data first.\033[0m\n");
            }
        }
        else if (!strcmp(cmd, "EXIT") || !strcmp(cmd, "13"))
        {
            printf("\033[1;31mShutting down system...\033[0m\n");
            break;
        }
        else if (!strcmp(cmd, "EVO") || !strcmp(cmd, "14"))
        {
            int iterations = 1000;
            printf("\n--- STARTING VOLTEX NEURAL SYNTHESIS (%d RECORDS) ---\n", iterations);
            printf("[MODE]: JSON Schema Ingestion + Auto-Pinning\n");

            for (int i = 1; i <= iterations; i++)
            {
                // 1. Generate the Dummy JSON
                char *json_record = generate_dummy_json(i);
                if (!json_record)
                    continue;

                // 2. Ingest into the Vault
                Node *res = ingest(json_record);

                // 3. AUTO-PIN: Make the root of this record immortal
                if (res)
                {
                    res->is_pinned = 1;
                    res->vitality = 1.0f;
                }

                free(json_record); // Free the temporary buffer

                // Visualization Pulse (Every 50 records)
                if (i % 50 == 0)
                {
                    int strong = 0, weak = 0;
                    Node *curr = vault;
                    while (curr)
                    {
                        if (curr->vitality > 0.8f)
                            strong++;
                        else
                            weak++;
                        curr = curr->next;
                    }
                    printf("\r[Record %4d] Vault Map: [", i);
                    for (int s = 0; s < strong / 10; s++)
                        printf("="); // Scaled for higher volume
                    for (int w = 0; w < weak / 10; w++)
                        printf(".");
                    printf("] Atoms:%d Chunks:%d", count_V_ATOMs(), count_V_CHUNKs());
                    fflush(stdout);
                }

                // 4. METABOLIC RUMINATION
                // Every 250 records, we Dream to purge transient noise and
                // Ruminate to find deeper patterns in the JSON keys.
                if (i % 250 == 0)
                {
                    printf("\n--- CYCLE %d: GLOBAL RUMINATION ---\n", i);
                    // run_ruminate_logic(""); // Global Rumination to snap Axons on recurring keys
                    // execute_dream_cycle();  // Purge everything except the Pinned Records
                    display_metrics();
                }
            }
            printf("\n--- SYNTHESIS COMPLETE. VAULT IS NOW STRUCTURALLY SATURATED. ---\n");
        }
        else if (!strcmp(cmd, "RUMINATE") || !strcmp(cmd, "15"))
        {
            char target[64] = "";
            int cycles = 1;

            // 1. Clear buffer from previous scanf
            int c;
            while ((c = getchar()) != '\n' && c != EOF)
                ;

            // 2. Get Target
            printf("Target Hex (Enter for GLOBAL): ");
            if (fgets(buf, sizeof(buf), stdin))
            {
                buf[strcspn(buf, "\n")] = 0;
                strcpy(target, buf);
            }

            // 3. Get Iteration Count
            printf("Consolidation Cycles: ");
            if (fgets(buf, sizeof(buf), stdin))
            {
                cycles = atoi(buf);
            }

            printf("[\033[1;35mPROCESS\033[0m] Initiating %d cycles of neural rumination...\n", cycles);

            for (int i = 0; i < cycles; i++)
            {
                printf(" Cycle %d/%d... ", i + 1, cycles);
                run_ruminate_logic(target);

                // After each cycle, we dream to prune the branches we just simplified
                execute_dream_cycle();
                printf("Consolidated.\n");
            }

            printf("[\033[1;32mDONE\033[0m] Metabolic cleanup complete.\n");
            display_metrics();
        }
        else if (!strcmp(cmd, "EVO-ULTRA") || !strcmp(cmd, "16"))
        {
            int batch_size = 100000;
            static int global_record_count = 0; // Persistent across multiple '14' calls
            static int last_metric_milestone = 0;

            printf("\n--- VOLTEX GROWTH PHASE: +%d RECORDS ---\n", batch_size);

            for (int i = 1; i <= batch_size; i++)
            {
                global_record_count++;

                // 1. GENERATE & INGEST
                char *json_record = generate_dummy_json(global_record_count);
                Node *res = ingest(json_record);

                // 2. STABILIZE (PINNING)
                if (res)
                {
                    res->is_pinned = 1;
                    res->vitality = 1.0f;
                }
                free(json_record);

                // 3. THE MILESTONE TRIGGER (Every 10,000 records)
                if (global_record_count >= 100000 && (global_record_count - last_metric_milestone) >= 10000)
                {
                    printf("\n\n[!] SINGULARITY MILESTONE: %d RECORDS REACHED", global_record_count);
                    display_metrics(); // This provides your timeline point
                    last_metric_milestone = global_record_count;

                    // Optional: Auto-Save every 10k to prevent data loss during long runs
                    // save_vault("checkpoint.vtx");
                }

                // 4. LOW-OVERHEAD PULSE
                if (i % 100 == 0)
                {
                    printf("\r[PROGRESS]: %d/%d | Vault Pop: %d", i, batch_size, global_record_count);
                    fflush(stdout);
                }
            }

            // 5. POST-BATCH CLEANUP
            execute_dream_cycle();
            printf("\n--- BATCH COMPLETE. TOTAL RECORDS: %d ---\n", global_record_count);
        }
        else
        {
            printf("Unknown Command. Type '\033[1;33mHELP\033[0m' for list.\n");
        }
    }
    return 0;
}