#ifndef EXAMOS_TPM_PUBLIC_H
#define EXAMOS_TPM_PUBLIC_H

#include <stddef.h>

int tpm_public_validate_rsa_ak(const char *public_area_hex,
                               const char *public_key_pem,
                               const char *submitted_name_hex,
                               char *out_name_hex,
                               size_t out_name_size,
                               int *out_key_bits);

#endif
