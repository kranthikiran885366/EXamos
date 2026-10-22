#include "../../server/include/attestation_service.h"
#include "../../server/include/attestation_config.h"
#include <stdio.h>
#include <string.h>

static unsigned int device_count;
static unsigned int release_count;

int attestation_register_device(const char *device_id, const char *ek_fingerprint,
                                const char *allowed_release) {
    if (!device_id || !device_id[0] || !ek_fingerprint || strlen(ek_fingerprint) != 64 ||
        !allowed_release || !allowed_release[0]) return -1;
    device_count++;
    return 0;
}

int attestation_register_device_identity(const char *device_id,
                                         const char *ek_fingerprint,
                                         const char *ak_qualified_name,
                                         const char *ak_public_pem,
                                         const char *ak_public_sha256,
                                         const char *allowed_release) {
    if (!device_id || !ek_fingerprint || strlen(ek_fingerprint) != 64 ||
        !ak_qualified_name || strlen(ak_qualified_name) != 68 ||
        !ak_public_pem || !ak_public_pem[0] ||
        !ak_public_sha256 || strlen(ak_public_sha256) != 64 ||
        !allowed_release || !allowed_release[0]) return -1;
    device_count++;
    return 0;
}

int attestation_register_release(const char *release_id, const char *uki_hash,
                                 const char *pcr0, const char *pcr4,
                                 const char *pcr7, const char *pcr11) {
    if (!release_id || !release_id[0] || !uki_hash || strlen(uki_hash) != 64 ||
        !pcr0 || strlen(pcr0) != 64 || !pcr4 || strlen(pcr4) != 64 ||
        !pcr7 || strlen(pcr7) != 64 || !pcr11 || strlen(pcr11) != 64) return -1;
    release_count++;
    return 0;
}

int attestation_revoke_release(const char *release_id) {
    (void)release_id;
    return 0;
}

int main(void) {
    if (attestation_config_load_all(NULL) != 0 || device_count == 0 || release_count == 0) {
        fprintf(stderr, "registry configuration was rejected or empty\n");
        return 1;
    }
    printf("registry configuration accepted: devices=%u releases=%u\n",
           device_count, release_count);
    return 0;
}
