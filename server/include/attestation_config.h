#ifndef EXAMOS_ATTESTATION_CONFIG_H
#define EXAMOS_ATTESTATION_CONFIG_H

/*
 * attestation_config.h — ExamOS P3 Dynamic Config Loader
 *
 * Loads enrolled devices and golden releases from JSON files at startup.
 * Files are located via environment variables:
 *   EXAMOS_DEVICES_CONFIG  — path to devices.json
 *   EXAMOS_RELEASES_CONFIG — path to releases.json
 *
 * Defaults to:
 *   /etc/examos/devices.json   (production)
 *   server/config/devices.json (development, relative to binary location)
 */

#include "attestation_service.h"

/*
 * Load enrolled devices from a JSON file.
 * Calls attestation_register_device() for each valid entry.
 * Returns number of devices loaded, or -1 on hard failure.
 */
int attestation_config_load_devices(const char *json_path);

/*
 * Load golden releases from a JSON file.
 * Calls attestation_register_release() for each valid entry.
 * Sets revoked flag where release.revoked == true.
 * Returns number of releases loaded, or -1 on hard failure.
 */
int attestation_config_load_releases(const char *json_path);

/*
 * Convenience: load both devices and releases from environment-specified
 * paths, falling back to the development defaults if env vars are absent.
 *
 * Resolution order:
 *   1. $EXAMOS_DEVICES_CONFIG / $EXAMOS_RELEASES_CONFIG
 *   2. /etc/examos/devices.json / /etc/examos/releases.json
 *   3. <binary_dir>/../config/devices.json  (dev mode)
 *
 * Returns 0 if at least one device and one release were loaded.
 * Returns -1 if no config was found anywhere (caller falls back to
 * compiled-in test defaults).
 */
int attestation_config_load_all(const char *binary_dir);

/* Disabled until runtime state retains the complete signed device-key identity. */
int attestation_config_save_devices(const char *json_path);

#endif /* EXAMOS_ATTESTATION_CONFIG_H */
