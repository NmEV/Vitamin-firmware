# USBNet

[中文版 README](README.zh.md) · English

A USB ethernet network on a Raspberry Pi Pico (RP2040) / Pico 2 (RP2350),
with a small encrypted flash-backed **web service** on top.

The board appears as a USB network interface (CDC-NCM by default; set
`USE_ECM` to `1` in `tusb_config.h` for ECM/RNDIS), assigns itself
`192.168.7.1`, runs a DHCP server that gives the host `192.168.7.16`, and
answers mDNS as `demo.local`. A tiny HTTP server on port 80 exposes three
endpoints whose payload is encrypted before it is persisted to flash.

## Quick start

1. Build (or download the CI artifact — see [Building](#building)) and flash
   the firmware: hold the BOOTSEL button, plug in the USB cable, and drag the
   `.uf2` file onto the `RPI-RP2` drive.
2. The host gets an address from the Pico's DHCP server (`192.168.7.16`).
   `ping 192.168.7.1` and `ping demo.local` should both work.
3. **No manual clearing needed after firmware upgrades** — the on-flash
   header carries a format version (see [Storage & encryption](#storage--encryption));
   a record written by an incompatible format is detected immediately and
   treated as empty (`/print` returns `{"status":"empty"}`), and the next
   `/write` simply overwrites it. Only call `/clear` when you want to wipe the
   data on purpose — `/clear` is POST-only and demands the exact key pair that
   the last `/write` returned (its `pk`/`sk` receipt):
   ```sh
   curl -X POST http://192.168.7.1/clear \
        -d '{"pk":"<the pk from /write>","sk":"<the sk from /write>"}'
   ```

## Web service API

Server: lwIP raw TCP on port 80, driven by the existing `NO_SYS` main loop
(no RTOS, no extra thread). Responses use `Connection: close`; requests must
contain a `Content-Length` header.

| Method | Path    | Behavior |
|--------|---------|----------|
| POST   | `/write` | Sends a JSON form, e.g. `{"name":"alice","value":"hello"}`. The configured fields (`WRITE_FIELDS` in `web_server.c`, default `name` and `value`) are extracted and **encrypted**, then persisted to flash. Returns `{"status":"ok","bytes":N,"pk":"<64 hex>","sk":"<64 hex>"}`: `pk`/`sk` are the **clear receipt** of the record just written — keep them. `400` on an invalid/empty body, `413` if the stored data exceeds 2 KiB. CORS-enabled (`Access-Control-Allow-Origin: *`, OPTIONS preflight) so browser apps on the host can POST and read the response. |
| GET    | `/print` | Returns the stored data as `application/json` (decrypted on the fly), or `{"status":"empty"}` if nothing valid is stored. Only compiled in when `DEBUG=1` (`tusb_config.h`); default builds answer `404`. |
| GET    | `/sign` | Endpoint description: `{"endpoint":"/sign","method":"POST","fields":["challenge","context","timestamp"]}`. |
| POST   | `/sign` | Ed25519-signs the message `<challenge>:<context>:<timestamp>:device_001` with the firmware's embedded key (migrated from the legacy firmware). Returns `{"signature":"<base64>","timestamp":"<echoed>","device_id":"device_001"}`. `400` on an empty/missing/malformed field. |
| POST   | `/clear` | Erases the stored data, but **only when the body carries the exact `pk`/`sk`** (hex) that the `/write` of the current record returned, e.g. `{"pk":"...","sk":"..."}`. Exact match → `{"status":"ok"}`; mismatch → `403` and the data stays untouched; missing/malformed pair → `400`; nothing valid stored → `200` (idempotent no-op). |
| any    | other    | `404`. `GET /clear` is answered `405`: wiping is POST-only so a browser link or an `<img>` can never erase the record. |

Example:

```sh
curl -X POST http://192.168.7.1/write -d '{"name":"alice","value":"hello"}'
#   -> {"status":"ok","bytes":32,"pk":"<64 hex chars>","sk":"<64 hex chars>"}
curl http://192.168.7.1/print
#   -> {"name":"alice","value":"hello"}
curl -X POST http://192.168.7.1/clear \
     -d '{"pk":"<the pk from /write>","sk":"<the sk from /write>"}'
#   -> {"status":"ok"}
```

**The clear receipt**: every `/write` generates a fresh key pair and returns it
(hex `pk`/`sk`) in the success response; the device also stores the pair in
the record header (offsets 36..99, see the layout below). `POST /clear`
compares the submitted pair byte-for-byte against the header pair and only
erases on an exact match:

- Only the **most recent `/write`'s** receipt works: a later `/write` rotates
  the keys, so an older receipt is answered `403`.
- On a mismatch the data is left completely untouched; `GET /clear` is always
  `405`.
- If the receipt is lost, a valid record can no longer be `/clear`ed, but a
  plain `/write` simply overwrites it (writing needs no receipt).

**Signing endpoint (`/sign`)** — migrated from the legacy firmware: POST a
JSON form with all three fields `challenge`, `context`, `timestamp`; the
firmware Ed25519-signs (TweetNaCl `crypto_sign`) the UTF-8 message
`<challenge>:<context>:<timestamp>:device_001` and answers with the base64
raw 64-byte signature plus the echoed timestamp and device id:

```sh
curl -X POST http://192.168.7.1/sign \
     -d '{"challenge":"abc","context":"login","timestamp":"2024-06-01T12:00:00Z"}'
# -> {"signature":"<base64 64-byte signature>","timestamp":"2024-06-01T12:00:00Z","device_id":"device_001"}
```

The signing key is fixed in the firmware image (the same constants as the
legacy firmware, so existing verifiers keep working): device id
`device_001`, Ed25519 public key (base64)
`f/LmPWawjJ9QjK6GniT26UdCcgIEd2tcoy3lbvCThNQ=`. Verify a signature with the
bundled standard-library tool (RFC 8032, no dependencies):

```sh
python sign_verify.py 'abc:login:2024-06-01T12:00:00Z:device_001' '<signature from /sign>'
# OK: signature is valid for this message and key
```

`/write` and `/sign` answer with permissive CORS headers
(`Access-Control-Allow-Origin: *`) and accept the OPTIONS preflight, so a
browser page on the host can call them and read the responses; `/print` and
`/clear` deliberately stay CORS-free so a random web page cannot read the
stored data and cannot preflight a wipe.

**The 2 KiB limit** applies to the *stored* JSON (field names, quotes and
braces included), not just the value. With the tool's 9-character `name`, the
fixed overhead is 31 bytes, so the largest accepted value is
`2048 - 31 = 2017` characters; a larger value is rejected with `413`
(`stress_test.py` probes this boundary automatically).

**JSON escapes**: the common escapes (`\"`, `\\`, `\/`, `\b`, `\f`, `\n`,
`\r`, `\t`) are decoded on /write and re-escaped on /print, so they round-trip
byte for byte; unsupported escapes (such as `\uXXXX`) or malformed JSON are
rejected with `400` instead of silently corrupting the value.
**Content-Length**: an empty or non-numeric value returns `400`; an
overflowing value saturates and is rejected with `413`, as is any declared
length beyond the receive buffer (~3.1 KB) — in both cases the connection is
closed immediately instead of hanging until the poll timeout.

## Storage & encryption

`storage.c` follows the official Pico `flash_program` pattern
(`flash_safe_execute` + `flash_range_erase/program`) at `XIP_BASE + 256 KB`.
The firmware is linked at the very start of flash, so this slot is only safe
while the **whole firmware footprint stays below 256 KB** — CI checks the
`arm-none-eabi-size` output and uploads `usbnet.map`, so code growth into the
storage slot fails the build. Nothing of the payload is ever persisted as
plaintext:

- On each write a **fresh `crypto_box` key pair** (X25519) and a **fresh
  24-byte nonce** are generated (tweetnacl; `randombytes()` is provided by
  this firmware using `get_rand_32()`).
- The payload is boxed in **256-byte sections** (XSalsa20-Poly1305,
  self-boxed); each section's nonce is the base nonce with the section index
  XORed into its last 8 bytes, so every section gets an independent keystream
  and is independently authenticated.
- The header carries a **format version byte**: after a firmware upgrade with
  an incompatible layout, an old record is recognized as foreign and treated
  as empty automatically (no manual `/clear` ritual; the next `/write`
  overwrites the sector). On-flash layout (one 4 KB sector):

  ```
  [0..3]    magic 'USBN'              (absent == empty/corrupt when erased)
  [4]       format version (currently 1; 0xFF when erased)
  [5..7]    reserved (0xFF)
  [8..11]   uint32 LE PLAINTEXT length
  [12..35]  base nonce (24 bytes)
  [36..67]  public key (32 bytes)
  [68..99]  secret key (32 bytes)
  [100..]   boxed sections: poly1305 MAC (16 bytes) + ciphertext per section
  ```

- `/print` reads back the nonce/keys and opens the sections one by one, each
  into a small stack buffer that is appended to the caller's buffer; a failed
  authentication (corrupt/foreign data) is reported as empty.

The secret key is stored alongside the payload (the goal of this feature is
that the *payload* is never persisted as plaintext, not key secrecy), so the
protection targets casual flash dumps rather than a determined attacker with
access to both the flash contents and the firmware. The same header key pair
doubles as the `/clear` receipt: `POST /clear` is only honoured when the
submitted keys byte-match the header pair, which stops stray web requests (an
accidental link, a drive-by `<img>`) from wiping the record — but not someone
who can read the flash, since the keys sit in the header next to the data.

## Memory configuration (`pico_config.h`)

The firmware is fed through the SDK's `PICO_CONFIG_HEADER_FILES` mechanism
(see `CMakeLists.txt`):

- **`PICO_STACK_SIZE = 0x1000` (4 KiB)** — the default 2 KiB is too tight for
  `crypto_scalarmult` (~1.5 KiB) running deep inside the lwIP/web callback
  chain. 4 KiB is the maximum: the default memmap places the core-0 stack in
  the 4 KiB `SCRATCH_Y` region (a larger size fails at link time).
- **`PICO_USE_STACK_GUARDS = 1`** — hardware-enforced stack overflow
  protection: on RP2350-ARM the SDK sets the Armv8-M `MSPLIM` register to the
  stack bottom (Armv6-M MPU on RP2040, PMP on RISC-V), so a stack overflow
  faults immediately instead of silently corrupting SRAM.

## Stress test

`stress_test.py` (Python 3.8+, standard library only) hammers the endpoints
and reports latency (avg/min/max/p50/p95), throughput and failures:

```sh
python stress_test.py                    # 100 cycles: write -> print -> verify
python stress_test.py -n 500 -s 512      # 500 iterations, 512-byte values
python stress_test.py -w 4 --mode write  # 4 workers, raw write throughput
python stress_test.py --mode clear       # wipe using the last /write's receipt
python stress_test.py --help             # all options
```

Its preflight checks the key-protected clear contract (a `GET /clear` is
refused with `405`; a probe `/write` must return the `pk`/`sk` receipt; a
`/clear` with wrong keys is refused with `403` and leaves the data intact; a
`/clear` with the exact receipt wipes the record, and a repeated `/clear` on
the now-empty slot stays a `200` no-op), rejects oversized `/write` bodies
with a clean `413`, requires every error response to be one parseable JSON
document (a regression net for response-body framing), verifies JSON-escape
round-trips (single worker) and binary-searches the real maximum accepted
value length (expected `~2017`). The tool remembers the receipt of every
successful `/write`, so `--mode clear` wipes what this run wrote; pass
`--pk`/`--sk` to clear a record written by an earlier session (any such
record the preflight cannot clear is overwritten by its probe write). `-s`
above the limit is refused at startup, so a doomed configuration cannot
produce a stream of `413`s. Note: byte-for-byte verification of written data
is only meaningful with `--workers 1`. The tool verifies writes through
`GET /print`, which only exists in `DEBUG=1` builds (`tusb_config.h`);
against a default (`DEBUG=0`) firmware its preflight aborts with a clear
message.

## Building

**GitHub Actions** (`.github/workflows/main.yml`) builds Release firmware for
both `pico` (RP2040) and `pico2` (RP2350) with ARM GCC 14.2.rel1 + Pico SDK
2.3.0 on `ubuntu-latest` (matching the local VS Code setup), triggered by
push/PR to `main`/`master` or manually; the toolchain and SDK are cached
between runs. Artifacts `usbnet-firmware-pico` / `usbnet-firmware-pico2` are
zips containing `build/usbnet.uf2` (flash this one), `build/usbnet.elf`,
`build/usbnet.bin` and `build/usbnet.map`. CI also fails the build if the
firmware grows into the 256 KB flash slot used by storage.

Locally: use the Raspberry Pi Pico VS Code extension (configured in
`CMakeLists.txt`, SDK 2.3.0 + GCC 14.2), or build manually:

```sh
mkdir build && cd build
cmake -DPICO_BOARD=pico2 -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

**Don't forget to change the board type to your correct board** (bottom-right
of the VS Code window, or the `PICO_BOARD` variable in `CMakeLists.txt`) —
the CI overrides it to `pico2`.

## Configuration & notes

- Protocol: `USE_ECM` in `tusb_config.h` (0 = CDC-NCM for iOS/Windows 11,
  1 = ECM + RNDIS for Windows/macOS).
- Debug read-back: `DEBUG` in `tusb_config.h` (default 0). The HTTP
  `GET /print` endpoint (read-back of the stored record) is only compiled in
  when `DEBUG=1`; with `DEBUG=0` the path answers `404`. Build a
  `DEBUG=1` image when you need to read the stored data back.
- Fields: `WRITE_FIELDS` in `web_server.c` (defaults to `name`, `value`).
- `flash_program.c` is the upstream reference for the flash write/read
  pattern and is **not part of the build** (it has its own `main`).
- `tweetnacl.c`/`tweetnacl.h` are the bundled single-file TweetNaCl
  implementation used for `crypto_box`, `crypto_box_open` and `randombytes`.
- For Pico W / Pico 2 W with CYW43-specific functionality: call
  `cyw43_arch_init()` first, then `usb_network_init(..., false)` (skip lwIP
  re-initialisation); when using `pico_cyw43_arch_lwip_poll` the `pico_lwip*`
  libraries can be dropped.
- stdio goes out over UART; sending `'s'` demonstrates a clean shutdown.
- Only a small subset of HTTP is supported (GET/POST, `Content-Length`,
  `Connection: close` responses); a client such as curl, a browser or Postman
  works fine.

## Credits

- Original project: [mattmyne/usbnet](https://github.com/mattmyne/usbnet)
  (itself based on TinyUSB's `net_lwip_webserver` example).
- Encryption via [TweetNaCl](https://tweetnacl.cr.yp.to/).
