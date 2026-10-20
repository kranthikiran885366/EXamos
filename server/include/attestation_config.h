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

/*
 * Persist the current in-memory device table back to the devices.json file
 * at the path resolved by attestation_config_load_all() (same resolution
 * order: $EXAMOS_DEVICES_CONFIG → /etc/examos/devices.json → dev path).
 *
 * Stage 2/3 fix: runtime enroll/revoke changes were lost on restart because
 * the table was only loaded, never saved.  This function writes atomically
 * (tmp + fsync + rename) so a crash during write leaves the old file intact.
 *
 * Returns 0 on success, -1 on failure (caller should log and continue;
 * the in-memory state is still valid for the current run).
 *
 * IMPORTANT: only persists status/fields that originated from attestation_register_device().
 * The signed registry fields (ek_fingerprint, ak_name, ak_pub_sha256) are written
 * verbatim from the in-memory record so the file remains verifiable on next load.
 */
int attestation_config_save_devices(const char *json_path);

#endif /* EXAMOS_ATTESTATION_CONFIG_H */
