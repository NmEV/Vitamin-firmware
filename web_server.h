// Minimal single-threaded (lwIP NO_SYS) HTTP server for the usbnet web service.
//
// Exposes three endpoints backed by the flash storage module:
//   POST /write  body = JSON form, extracts the configured fields (default:
//                {"name", "value"}), persists them (<= 2 KiB) to flash. 200 on
//                success, 400 bad/invalid body, 413 payload too large.
//   GET  /print  returns the stored data (application/json). 200 always.
//   GET  /clear  erases the stored data. 200 always.
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
