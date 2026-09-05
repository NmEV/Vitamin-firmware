// Minimal single-threaded (lwIP NO_SYS) HTTP server for the usbnet web service.
//
// Exposes three endpoints backed by the flash storage module:
//   POST /write  body = JSON form, extracts the configured fields (default:
//                {"name", "value"}), persists them (<= 2 KiB) to flash. 200 on
//                success, 400 bad/invalid body, 413 payload too large. The
//                success response includes the fresh pk/sk (64 hex chars each)
//                that sealed the record: keep them, they are the clear
//                receipt for this record. CORS-enabled (Access-Control-Allow-*)
//                with OPTIONS preflight, so browser apps on the host can POST
//                and read the response; /print and /clear stay CORS-free.
//   GET  /print  returns the stored data (application/json). Only compiled in
//                when DEBUG=1 in tusb_config.h (default 0): in release builds
//                this path is answered 404 like any unknown route.
//   POST /clear  erases the stored data, but only when the JSON body carries
//                the exact pk/sk returned by the /write of the current
//                record: 403 on a mismatch (data untouched), 400 on a
//                missing/malformed pair, 200 when nothing valid is stored
//                (idempotent no-op). GET /clear -> 405: wiping must never be
//                triggerable by a plain link/image request.
//   GET  /sign   endpoint description.
//   POST /sign   signs challenge:context:timestamp:device_id with the
//                firmware's embedded Ed25519 key and returns the base64
//                signature (legacy firmware endpoint, CORS-enabled).
//
// Nothing runs on its own thread: the server is driven by the caller's main
// loop via the existing usb_network_update() (which services lwIP TCP).

#ifndef WEB_SERVER_H
#define WEB_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

// Creates the listening TCP socket on port 80. Safe to call once after the
// network interface is up. Returns true on success.
bool web_server_init(void);

#ifdef __cplusplus
}
#endif

#endif // WEB_SERVER_H
