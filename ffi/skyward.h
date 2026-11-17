/*
 * skyward-core Rust FFI — C ABI.
 * Keep in sync with src/ffi.rs. Generated for the aarch64 Android release.
 */
#ifndef SKYWARD_H
#define SKYWARD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum SkywardStatus {
    SKYWARD_OK = 0,
    SKYWARD_NULL_POINTER = 1,
    SKYWARD_INVALID_UTF8 = 2,
    SKYWARD_CONFIG_ERROR = 3,
    SKYWARD_NOT_INITIALIZED = 4,
    SKYWARD_RUNTIME_ERROR = 5,
    SKYWARD_PANIC = 6,
    SKYWARD_NOT_IMPLEMENTED = 7,
} SkywardStatus;

typedef struct SkywardOptions {
    int32_t tun_fd;             /* -1 = no TUN */
    uint32_t tun_mtu;
    int embed_mode;             /* bool */
    const char *home_dir;       /* NUL-terminated, or NULL */
} SkywardOptions;

typedef struct DnsAnswer {
    uint8_t ip[16];             /* IPv4 in first 4 bytes, IPv6 in all 16 */
    uint8_t len;                /* 4 or 16 */
    uint8_t _pad[3];
} DnsAnswer;

typedef void (*SkywardCallback)(const uint8_t *data, size_t len, void *user_data);

typedef struct SkywardHooks {
    SkywardCallback connection; /* JSON: {"event":"add|remove","id","host"} */
    SkywardCallback dns;
    SkywardCallback provider;
    void *user_data;
} SkywardHooks;

typedef struct SkywardHandle SkywardHandle;

/* Returns a NUL-terminated static version string. */
const char *skyward_version(void);

SkywardHandle *skyward_create(const SkywardOptions *opts);
SkywardStatus skyward_test_config(const uint8_t *yaml, size_t len);
SkywardStatus skyward_apply_config(SkywardHandle *handle, const uint8_t *yaml, size_t len);
SkywardStatus skyward_start_inbound(SkywardHandle *handle);
void          skyward_close_inbound(SkywardHandle *handle);
SkywardStatus skyward_query_dns(SkywardHandle *handle, const char *name,
                                uint16_t qtype, DnsAnswer *out);
SkywardStatus skyward_handle_tun_packet(SkywardHandle *handle,
                                        const uint8_t *pkt, size_t len);
void          skyward_set_hooks(SkywardHandle *handle, const SkywardHooks *hooks);
void          skyward_emit_event(SkywardHandle *handle, const uint8_t *json, size_t len);
/* gomobile-style method call; returns a JSON buffer freed by skyward_free_buffer. */
uint8_t *skyward_invoke_method(const uint8_t *data, size_t len, size_t *out_len);
void      skyward_free_buffer(uint8_t *ptr, size_t len);

void          skyward_destroy(SkywardHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* SKYWARD_H */
