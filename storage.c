// Flash-backed encrypted storage module. See storage.h for the public API.
//
// The layout follows the official Raspberry Pi Pico "flash_program" example:
//  - storage lives at XIP_BASE + STORAGE_FLASH_OFFSET (256 KB into flash).
//    The SDK links the program at the very start of XIP flash (right after
//    the 256-byte boot stage 2), so this slot only stays clear while the
//    whole firmware footprint remains below 256 KB - check the size with
//    arm-none-eabi-size and the CI build's usbnet.map if you add code.
//  - a whole FLASH_SECTOR_SIZE (4 KB) sector is erased before programming, and
//    writing is performed via flash_safe_execute() so it cannot collide with
//    code being fetched from flash.
//
// Payloads are encrypted with tweetnacl's crypto_box (X25519 + XSalsa20-
// Poly1305, "box to itself"). Every write generates a fresh key pair
// (crypto_box_keypair) and a fresh 24-byte nonce; the public key, secret key
// and nonce are all persisted together with the ciphertext sections, so
// /print can decrypt after a power cycle. On-flash layout:
//
//   [0..3]     magic 'U' 'S' 'B' 'N'  (absent == empty/corrupt when erased)
//   [4]        format version (STORAGE_FORMAT_VERSION; 0xFF when erased)
//   [5..7]     reserved (0xFF)
//   [8..11]    uint32 little-endian PLAINTEXT length
//   [12..35]   crypto_box nonce (24 bytes, fresh on every write)
//   [36..67]   public key  (32 bytes)
//   [68..99]   secret key  (32 bytes)
//   [100..]    boxed sections: per section, Poly1305 MAC (16 bytes) followed
//              by ciphertext bytes; section i covers plaintext bytes
//              [i*STORAGE_SECTION_SIZE .. i*STORAGE_SECTION_SIZE+chunk)
//
// The version byte lets a firmware whose on-flash format is incompatible with
// an older record detect it immediately (storage_available() reports false)
// instead of misreading the old bytes; the next /write simply replaces the
// slot. Data written by pre-versioning firmware has garbage where the version
// byte lives (the low byte of the old length field), so it is treated as
// empty too.
//
// Note: the secret key is persisted alongside the payload. The point of this
// feature is that the *payload* never lands on flash as plaintext, not key
// secrecy.

#include <string.h>

#include "hardware/flash.h"
#include "pico/flash.h"
#include "pico/rand.h"
#include "pico/stdlib.h"

#include "storage.h"
#include "tweetnacl.h"

#define STORAGE_FLASH_OFFSET (256 * 1024)

#define STORAGE_FORMAT_VERSION 1 // bump whenever the on-flash layout changes
#define STORAGE_MAGIC_LEN 4
#define STORAGE_VERSION_LEN 1
#define STORAGE_RSVD_LEN 3 // reserved bytes after the version (stay 0xFF)
#define STORAGE_LEN_LEN 4
#define STORAGE_NONCE_LEN 24
#define STORAGE_KEY_LEN 32
#define STORAGE_SECTION_SIZE 256 // plaintext bytes per section
#define STORAGE_BOX_OVERHEAD 16  // Poly1305 MAC appended per section by crypto_box
#define STORAGE_LEN_OFF (STORAGE_MAGIC_LEN + STORAGE_VERSION_LEN + STORAGE_RSVD_LEN) // 8
#define STORAGE_NONCE_OFF (STORAGE_LEN_OFF + STORAGE_LEN_LEN)                        // 12
#define STORAGE_PK_OFF (STORAGE_NONCE_OFF + STORAGE_NONCE_LEN)                       // 36
#define STORAGE_SK_OFF (STORAGE_PK_OFF + STORAGE_KEY_LEN)                            // 68
#define STORAGE_HEADER_SIZE (STORAGE_SK_OFF + STORAGE_KEY_LEN)                       // 100

#define STORAGE_MAX_SECTIONS                                                        \
    ((STORAGE_MAX_PAYLOAD + STORAGE_SECTION_SIZE - 1) / STORAGE_SECTION_SIZE)

#define STORAGE_TOTAL_BYTES                                                             \
    ((STORAGE_HEADER_SIZE + STORAGE_MAX_SECTIONS * STORAGE_BOX_OVERHEAD +                \
      STORAGE_MAX_PAYLOAD + FLASH_PAGE_SIZE - 1) &                                       \
     ~(FLASH_PAGE_SIZE - 1))

_Static_assert(STORAGE_TOTAL_BYTES <= FLASH_SECTOR_SIZE,
               "storage region must fit inside a single flash sector");
_Static_assert(STORAGE_MAX_PAYLOAD % STORAGE_SECTION_SIZE == 0,
               "sections must tile the payload exactly");

// From tweetnacl.c: u8 == unsigned char, u64 == unsigned long long. Provided
// here because crypto_box_keypair() calls this external function.
void randombytes(unsigned char *out, unsigned long long outlen) {
    while (outlen >= sizeof(uint32_t)) {
        uint32_t r = get_rand_32();
        memcpy(out, &r, sizeof(r));
        out += sizeof(r);
        outlen -= sizeof(r);
    }
    if (outlen) {
        uint32_t r = get_rand_32();
        memcpy(out, &r, (size_t)outlen);
    }
}

// Flash-mapped view of the storage slot.
static const uint8_t *const storage_flash = (const uint8_t *)(XIP_BASE + STORAGE_FLASH_OFFSET);

// RAM staging buffer (only nonce, keys and ciphertext ever reach flash).
static uint8_t storage_buf[STORAGE_TOTAL_BYTES];

// These callbacks are handed to flash_safe_execute() exactly as the official
// flash_program example does; flash_safe_execute() guarantees they run only
// while flash is safe to erase/program.
static void __no_inline_not_in_flash_func(storage_erase_cb)(void *param) {
    (void)param;
    flash_range_erase(STORAGE_FLASH_OFFSET, FLASH_SECTOR_SIZE);
}

static void __no_inline_not_in_flash_func(storage_program_cb)(void *param) {
    uintptr_t *p = (uintptr_t *)param;
    uint32_t count = (uint32_t)p[0];
    const uint8_t *data = (const uint8_t *)(uintptr_t)p[1];
    flash_range_program(STORAGE_FLASH_OFFSET, data, count);
}

// crypto_box nonce layout: bytes [0..15] feed HSalsa20, bytes [16..23] are the
// Salsa20 nonce. XORing the section index into those last 8 bytes gives every
// section an independent keystream while only the single base nonce is stored.
static void storage_section_nonce(const uint8_t base[STORAGE_NONCE_LEN], uint32_t idx,
                                  uint8_t out[STORAGE_NONCE_LEN]) {
    memcpy(out, base, STORAGE_NONCE_LEN);
    for (int b = 0; b < 8; ++b) {
        out[STORAGE_NONCE_LEN - 8 + b] ^= (uint8_t)(idx >> (b * 8));
    }
}

// A slot is usable only when the magic and the format version both match;
// anything else (erased flash, an old-format record, corruption) reads empty.
static bool storage_slot_valid(void) {
    return memcmp(storage_flash, "USBN", STORAGE_MAGIC_LEN) == 0 &&
           storage_flash[STORAGE_MAGIC_LEN] == STORAGE_FORMAT_VERSION;
}

bool storage_available(void) {
    if (!storage_slot_valid()) {
        return false;
    }
    uint32_t len;
    memcpy(&len, storage_flash + STORAGE_LEN_OFF, sizeof(len));
    return len > 0 && len <= STORAGE_MAX_PAYLOAD;
}

// Constant-time-ish comparison against the key pair in the record header:
// the loop always runs over every byte of both keys, so a mismatch does not
// reveal which byte differed.
bool storage_keys_match(const uint8_t pk[STORAGE_KEY_LEN], const uint8_t sk[STORAGE_KEY_LEN]) {
    if (!storage_available()) {
        return false; // nothing valid stored: there is no key pair to match
    }
    const uint8_t *fpk = storage_flash + STORAGE_PK_OFF;
    const uint8_t *fsk = storage_flash + STORAGE_SK_OFF;
    uint8_t diff = 0;
    for (size_t i = 0; i < STORAGE_KEY_LEN; ++i) {
        diff |= (uint8_t)(pk[i] ^ fpk[i]);
        diff |= (uint8_t)(sk[i] ^ fsk[i]);
    }
    return diff == 0;
}

size_t storage_read(uint8_t *dst, size_t cap) {
    if (!storage_available()) {
        return 0;
    }

    uint32_t len;
    memcpy(&len, storage_flash + STORAGE_LEN_OFF, sizeof(len));
    if (len > cap) {
        len = cap;
    }

    // Nonce and both keys live in the header; they are only read, so flash
    // pointers are fine.
    const uint8_t *nonce = storage_flash + STORAGE_NONCE_OFF;
    const uint8_t *pk = storage_flash + STORAGE_PK_OFF;
    const uint8_t *sk = storage_flash + STORAGE_SK_OFF;

    // Decrypt section by section: each boxed section is opened in a stack
    // buffer (which holds the ZeroBytes padding, the MAC and the ciphertext)
    // and the plaintext is appended to dst, assembled in memory only.
    size_t pos = STORAGE_HEADER_SIZE;
    for (uint32_t i = 0; (size_t)i * STORAGE_SECTION_SIZE < len; ++i) {
        size_t off = (size_t)i * STORAGE_SECTION_SIZE;
        size_t chunk = len - off;
        if (chunk > STORAGE_SECTION_SIZE) {
            chunk = STORAGE_SECTION_SIZE;
        }

        uint8_t sec_nonce[STORAGE_NONCE_LEN];
        storage_section_nonce(nonce, i, sec_nonce);

        // Rebuild the crypto_box layout c[0..15]=0 | c[16..31]=MAC | c[32..]=ct
        uint8_t box[32 + STORAGE_SECTION_SIZE]; // stack, one section at a time
        memset(box, 0, 32);
        memcpy(box + 16, storage_flash + pos, STORAGE_BOX_OVERHEAD);
        memcpy(box + 32, storage_flash + pos + STORAGE_BOX_OVERHEAD, chunk);

        // box_open(m, c, d, n, y, x): y = sender public key, x = recipient
        // secret key. Self-boxed, so both are the stored pk/sk. In-place is
        // safe: the MAC is verified before the stream XOR overwrites c.
        if (crypto_box_open(box, box, 32 + chunk, sec_nonce, pk, sk) != 0) {
            return 0; // authentication failed: treat as empty/corrupt
        }
        memcpy(dst + off, box + 32, chunk);
        pos += STORAGE_BOX_OVERHEAD + chunk;
    }
    return len;
}

bool storage_write(const uint8_t *src, size_t len, uint8_t out_pk[STORAGE_KEY_LEN],
                     uint8_t out_sk[STORAGE_KEY_LEN]) {
    if (len == 0 || len > STORAGE_MAX_PAYLOAD) {
        return false;
    }

    // Fresh key pair + fresh nonce for this write.
    uint8_t pk[STORAGE_KEY_LEN], sk[STORAGE_KEY_LEN];
    if (crypto_box_keypair(pk, sk) != 0) {
        return false;
    }
    uint8_t nonce[STORAGE_NONCE_LEN];
    randombytes(nonce, STORAGE_NONCE_LEN);

    // Stage the full sector content in RAM; only nonce, keys and ciphertext
    // (never plaintext) are programmed to flash.
    memset(storage_buf, 0xFF, sizeof(storage_buf));
    memcpy(storage_buf, "USBN", STORAGE_MAGIC_LEN);
    storage_buf[STORAGE_MAGIC_LEN] = STORAGE_FORMAT_VERSION; // [5..7] stay 0xFF
    uint32_t len_le = (uint32_t)len;
    memcpy(storage_buf + STORAGE_LEN_OFF, &len_le, sizeof(len_le));
    memcpy(storage_buf + STORAGE_NONCE_OFF, nonce, STORAGE_NONCE_LEN);
    memcpy(storage_buf + STORAGE_PK_OFF, pk, STORAGE_KEY_LEN);
    memcpy(storage_buf + STORAGE_SK_OFF, sk, STORAGE_KEY_LEN);

    size_t pos = STORAGE_HEADER_SIZE;
    for (uint32_t i = 0; (size_t)i * STORAGE_SECTION_SIZE < len; ++i) {
        size_t off = (size_t)i * STORAGE_SECTION_SIZE;
        size_t chunk = len - off;
        if (chunk > STORAGE_SECTION_SIZE) {
            chunk = STORAGE_SECTION_SIZE;
        }

        uint8_t sec_nonce[STORAGE_NONCE_LEN];
        storage_section_nonce(nonce, i, sec_nonce);

        // Build the TweetNaCl secretbox input m[0..31] = 0 (ZeroBytes padding),
        // plaintext at m[32..], then box in place. Output ends up as
        // c[0..15]=0 | c[16..31]=MAC | c[32..]=ciphertext.
        uint8_t box[32 + STORAGE_SECTION_SIZE]; // stack, one section at a time
        memset(box, 0, 32);
        memcpy(box + 32, src + off, chunk);
        if (crypto_box(box, box, 32 + chunk, sec_nonce, pk, sk) != 0) {
            return false;
        }
        memcpy(storage_buf + pos, box + 16, STORAGE_BOX_OVERHEAD + chunk);
        pos += STORAGE_BOX_OVERHEAD + chunk;
    }

    int rc = flash_safe_execute(storage_erase_cb, NULL, UINT32_MAX);
    if (rc != PICO_OK) {
        return false;
    }

    uintptr_t params[2] = {STORAGE_TOTAL_BYTES, (uintptr_t)storage_buf};
    rc = flash_safe_execute(storage_program_cb, params, UINT32_MAX);
    if (rc != PICO_OK) {
        return false;
    }

    // Hand the writer its receipt: exactly the key pair that now seals the
    // record on flash (POST /clear will demand these same keys back).
    memcpy(out_pk, pk, STORAGE_KEY_LEN);
    memcpy(out_sk, sk, STORAGE_KEY_LEN);
    return true;
}

bool storage_clear(void) {
    int rc = flash_safe_execute(storage_erase_cb, NULL, UINT32_MAX);
    return rc == PICO_OK;
}
