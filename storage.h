// Persistent, encrypted flash-backed storage for the web service.
//
// Wraps the official Raspberry Pi Pico flash_program pattern (flash_safe_execute
// + flash_range_erase/program) so the web /write endpoint can persist a small
// (<= 2 KiB) payload that survives a power cycle, and /print can read it back.
//
// Nothing of the payload is stored in plaintext: on each write a fresh
// crypto_box key pair and a fresh random 24-byte nonce are generated
// (tweetnacl), the payload is boxed (X25519 + XSalsa20-Poly1305) in 256-byte
// sections, and nonce + public key + secret key + ciphertext sections are
// persisted. /print reads the nonce (and keys) back and opens the sections
// one by one, each into a stack buffer that is appended to the caller's
// buffer. See storage.c for the exact layout.

#ifndef STORAGE_H
#define STORAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Maximum size of a single stored payload (2 KiB, not including the on-flash
// header: magic + format version + length + nonce + keys).
#define STORAGE_MAX_PAYLOAD (2 * 1024)

// Returns true if valid data is currently stored (magic and format version
// match, length is sane). Returns false when the slot is empty/cleared (flash
// erased to 0xFF), holds an incompatible older-format record, or is
// corrupted. Incompatible records are simply treated as empty; the next
// /write replaces them, so no manual /clear is needed after a format change.
bool storage_available(void);

// Copies the stored payload into dst (up to cap bytes). Returns the number of
// bytes copied, or 0 if nothing usable is stored. dst must be len <= cap.
size_t storage_read(uint8_t *dst, size_t cap);

// Returns true only when a valid record is stored AND its on-flash key pair
// is exactly the given one (32 bytes each). This authorizes destructive
// operations (POST /clear): the caller must present the pk/sk pair that the
// storage_write() of the current record returned as its receipt.
bool storage_keys_match(const uint8_t pk[32], const uint8_t sk[32]);

// Persists len bytes to flash. len must be > 0 and <= STORAGE_MAX_PAYLOAD.
// Returns true on success, false if len is out of range or the erase/program
// failed. On success the previous contents are replaced, and the fresh key
// pair that sealed the new record is copied into out_pk/out_sk (32 bytes
// each): this is the receipt the writer must keep, because a later
// storage_keys_match() / POST /clear will only accept exactly this pair.
// On failure out_pk/out_sk are left untouched.
bool storage_write(const uint8_t *src, size_t len, uint8_t out_pk[32], uint8_t out_sk[32]);

// Erases the storage slot, returning it to the empty state. Returns true on
// success.
bool storage_clear(void);

// ---------------------------------------------------------------------------
// Diagnostic state query (used by the /print?debug=1 interface). Exposes the
// slot state and the plaintext-length bookkeeping from the record header only:
// no key material, nonce or ciphertext is ever returned.
// ---------------------------------------------------------------------------
typedef enum {
    STORAGE_STATE_EMPTY = 0, // erased (0xFF) or nothing written yet
    STORAGE_STATE_VALID,     // magic + format version match and length is sane
    STORAGE_STATE_OTHER      // bytes present but magic/version/length do not
                             // match (older format, partial write, corruption)
} storage_state_t;

typedef struct {
    storage_state_t state;
    uint8_t format_version; // raw header version byte (0xFF when erased)
    uint32_t payload_len;   // meaningful only when state == STORAGE_STATE_VALID
} storage_info_t;

// Fills *out with the current slot state. Returns true on success.
bool storage_get_info(storage_info_t *out);

#endif // STORAGE_H
