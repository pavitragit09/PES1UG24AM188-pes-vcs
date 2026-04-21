// object.c — Content-addressable object store
//// Phase 1 extra commit 1
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── IMPLEMENTED ─────────────────────────────────────────────────────────────

// Write an object to the store.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // Step 1: Build the header string: "blob 16\0" / "tree 16\0" / "commit 16\0"
    const char *type_str;
    if (type == OBJ_BLOB)        type_str = "blob";
    else if (type == OBJ_TREE)   type_str = "tree";
    else                         type_str = "commit";

    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    // header_len does NOT include the null byte, but we need to store it
    size_t full_len = header_len + 1 + len;  // +1 for the '\0' after the header

    // Step 2: Allocate a buffer for header + '\0' + data
    uint8_t *full = malloc(full_len);
    if (!full) return -1;
    memcpy(full, header, header_len);
    full[header_len] = '\0';                 // the null byte separator
    memcpy(full + header_len + 1, data, len);

    // Step 3: Compute SHA-256 of the full object
    ObjectID id;
    compute_hash(full, full_len, &id);

    // Step 4: Check for deduplication — if already stored, return immediately
    if (object_exists(&id)) {
        *id_out = id;
        free(full);
        return 0;
    }

    // Step 5: Create the shard directory (.pes/objects/XX/)
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(&id, hex);

    char shard_dir[256];
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(shard_dir, 0755);  // OK if it already exists

    // Step 6: Get the final object path
    char obj_path[512];
    object_path(&id, obj_path, sizeof(obj_path));

    // Step 7: Write to a temp file in the same shard directory
    char tmp_path[520];
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp_XXXXXX", shard_dir);
    int fd = mkstemp(tmp_path);
    if (fd < 0) { free(full); return -1; }

    ssize_t written = write(fd, full, full_len);
    free(full);
    if (written < 0 || (size_t)written != full_len) {
        close(fd);
        unlink(tmp_path);
        return -1;
    }

    // Step 8: fsync the temp file to ensure data reaches disk
    fsync(fd);
    close(fd);

    // Step 9: Atomically rename temp file to final path
    if (rename(tmp_path, obj_path) != 0) {
        unlink(tmp_path);
        return -1;
    }

    // Step 10: fsync the shard directory to persist the rename
    int dir_fd = open(shard_dir, O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    *id_out = id;
    return 0;}
// Read an object from the store.
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // Step 1: Get the file path
    char path[512];
    object_path(id, path, sizeof(path));

    // Step 2: Open and read the entire file
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    size_t file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *file_buf = malloc(file_size);
    if (!file_buf) { fclose(f); return -1; }
    if (fread(file_buf, 1, file_size, f) != file_size) {
        fclose(f); free(file_buf); return -1;
    }
    fclose(f);

    // Step 3: Integrity check — recompute hash and compare to filename
    ObjectID computed;
    compute_hash(file_buf, file_size, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(file_buf);
        return -1; // Corruption detected!
    }

    // Step 4: Find the \0 that separates header from data
    uint8_t *null_byte = memchr(file_buf, '\0', file_size);
    if (!null_byte) { free(file_buf); return -1; }

    // Step 5: Parse the type from the header (e.g., "blob 16")
    if (strncmp((char *)file_buf, "blob", 4) == 0)        *type_out = OBJ_BLOB;
    else if (strncmp((char *)file_buf, "tree", 4) == 0)   *type_out = OBJ_TREE;
    else if (strncmp((char *)file_buf, "commit", 6) == 0) *type_out = OBJ_COMMIT;
    else { free(file_buf); return -1; }

    // Step 6: Extract data portion (everything after the \0)
    uint8_t *data_start = null_byte + 1;
    size_t data_len = file_size - (data_start - file_buf);

    uint8_t *out_buf = malloc(data_len);
    if (!out_buf) { free(file_buf); return -1; }
    memcpy(out_buf, data_start, data_len);

    *data_out = out_buf;
    *len_out = data_len;

    free(file_buf);
    return 0;
}
