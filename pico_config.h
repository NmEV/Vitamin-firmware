// Project-wide pico-sdk configuration header.
//
// This file is referenced by CMakeLists.txt via the SDK's
// PICO_CONFIG_HEADER_FILES variable: the SDK appends an #include of this file
// to its generated pico/config_autogen.h, so it is reached from pico.h by
// EVERY translation unit - including assembly (crt0.S), which defines the
// stack size from PICO_STACK_SIZE. Therefore this file may only contain
// preprocessor directives.
#ifndef USBNET_PICO_CONFIG_H
#define USBNET_PICO_CONFIG_H

// The tweetnacl crypto_box path calls crypto_scalarmult, which uses about
// 1.5 KB of stack, and it runs deep inside the lwIP/web callback chain. The
// default 2 KB stack is too tight, so reserve the full 4 KB.
//
// NOTE: the pico-sdk linker places the core-0 stack (.stack_dummy) in the
// 4 KB SCRATCH_Y region, so PICO_STACK_SIZE cannot exceed 0x1000 with the
// default memmap (an 8 KB setting fails to link with
// "section `.stack_dummy' will not fit in region `SCRATCH_Y'").
#ifndef PICO_STACK_SIZE
#define PICO_STACK_SIZE 0x1000
#endif

// Hardware-enforced stack overflow protection.
//
// On RP2350-ARM the SDK's runtime init sets the Armv8-M MSPLIM register to the
// stack bottom, so every stack push below the limit raises a UsageFault
// instead of silently corrupting adjacent SRAM (this is what the crypto_box
// stack usage is measured against). On RP2040 the SDK uses the Armv6-M MPU,
// on RISC-V the PMP. Any stack overflow now traps immediately at runtime.
#ifndef PICO_USE_STACK_GUARDS
#define PICO_USE_STACK_GUARDS 1
#endif

#endif // USBNET_PICO_CONFIG_H
