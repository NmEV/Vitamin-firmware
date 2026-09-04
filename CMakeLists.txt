# Generated Cmake Pico project file

cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Initialise pico_sdk from installed location
# (note this can come from environment, CMake cache etc)

# == DO NOT EDIT THE FOLLOWING LINES for the Raspberry Pi Pico VS Code Extension to work ==
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.3.0)
set(toolchainVersion 14_2_Rel1)
set(picotoolVersion 2.3.0)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
set(PICO_BOARD pico CACHE STRING "Board type")

# Inject project-wide pico-sdk configuration (pico_config.h) into the SDK's
# generated pico/config_autogen.h. It defines PICO_STACK_SIZE (4 KiB, the
# maximum the default memmap allows: the core-0 stack lives in the 4 KiB
# SCRATCH_Y region) and PICO_USE_STACK_GUARDS for every translation unit
# including crt0.S: tweetnacl's crypto_scalarmult needs a deep stack, and it
# runs inside the lwIP/web callback chain. Must be set before
# pico_sdk_init() so the generated config header picks it up.
set(PICO_CONFIG_HEADER_FILES "${CMAKE_CURRENT_SOURCE_DIR}/pico_config.h" CACHE STRING
    "extra headers included from pico/config.h")

# Pull in Raspberry Pi Pico SDK (must be before project)
include(pico_sdk_import.cmake)

project(usbnet C CXX ASM)

# Initialise the Raspberry Pi Pico SDK
pico_sdk_init()

# Add executable. Default name is the project name, version 0.1

add_executable(usbnet
    main.c
    usb_network.c
    usb_descriptors.c
    dhcpserver/dhcpserver.c
    storage.c
    web_server.c
    tweetnacl.c
    ${PICO_TINYUSB_PATH}/lib/networking/rndis_reports.c
)

pico_set_program_name(usbnet "usbnet")
pico_set_program_version(usbnet "0.1")

# Modify the below lines to enable/disable output over UART/USB
pico_enable_stdio_uart(usbnet 1)
pico_enable_stdio_usb(usbnet 0)

# Add libraries to the build
target_link_libraries(usbnet
    pico_stdlib
    tinyusb_device
    pico_lwip
    pico_lwip_nosys
    pico_lwip_mdns
    pico_unique_id
    pico_flash
    pico_rand
)

# Add include directories to the build
target_include_directories(usbnet PRIVATE
    ${PICO_TINYUSB_PATH}/lib/networking # for rndis_protocol.h
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/.. # for our common lwipopts or any other standard includes, if required
)

pico_add_extra_outputs(usbnet)

# Emit a linker map file (usbnet.map next to the other outputs). It is used to
# verify layout assumptions (e.g. that the whole firmware stays below the
# 256 KB flash region reserved for the encrypted storage slot in storage.c)
# and is uploaded by CI as a build artifact.
target_link_options(usbnet PRIVATE "-Wl,-Map=${CMAKE_CURRENT_BINARY_DIR}/usbnet.map")
