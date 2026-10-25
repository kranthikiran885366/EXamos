#ifndef EXAMOS_TPM_CONTROLLER_H
#define EXAMOS_TPM_CONTROLLER_H

#include "../controllers/controller.h"

/* POST /api/v1/attestation/nonce      -> issue challenge */
/* POST /api/v1/attestation/verify     -> verify TPM evidence */
/* POST /api/v1/attestation/re-attest  -> re-attestation */
/* GET  /api/v1/attestation/status     -> status */
void tpm_handle(int client_fd, const char *method, const char *path,
                const char *body, const char *auth_header,
                const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_TPM_CONTROLLER_H */
