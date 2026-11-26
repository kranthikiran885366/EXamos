//! ExamOS measured-profile watchdog. No third-party crates or unsafe code.
//! Reuses systemd's existing lockdown-failed target for enforcement.
use std::{env, fs, path::{Path, PathBuf}, process::{self, Command}, thread,
          time::Duration};

fn read(root: &Path, name: &str) -> Result<String, String> {
    fs::read_to_string(root.join(name)).map_err(|e| format!("{name}: {e}"))
}

fn entries(path: PathBuf) -> Result<Vec<PathBuf>, String> {
    fs::read_dir(&path).map_err(|e| format!("{}: {e}", path.display()))?
        .map(|e| e.map(|v| v.path()).map_err(|e| e.to_string())).collect()
}

fn required_tokens(cmdline: &str) -> Result<(), String> {
    let tokens: Vec<&str> = cmdline.split_whitespace().collect();
    for expected in ["iommu.passthrough=0", "iommu.strict=1", "efi=disable_early_pci_dma"] {
        if !tokens.contains(&expected) { return Err(format!("missing kernel parameter {expected}")); }
    }
    // Reject duplicates as well as conflicting overrides: last-token kernel
    // parsing must not turn an earlier apparently secure value into a bypass.
    for prefix in ["iommu.passthrough=", "iommu.strict=", "efi="] {
        if tokens.iter().filter(|v| v.starts_with(prefix)).count() != 1 {
            return Err(format!("ambiguous kernel parameter {prefix}"));
        }
    }
    for bad in ["iommu=off", "intel_iommu=off", "amd_iommu=off", "ima_appraise=off"] {
        if tokens.contains(&bad) { return Err(format!("forbidden kernel parameter {bad}")); }
    }
    Ok(())
}

fn local_posture(root: &Path) -> Result<(), String> {
    let lockdown = read(root, "sys/kernel/security/lockdown")?;
    if !lockdown.split_whitespace().any(|s| s == "[confidentiality]") {
        return Err("kernel confidentiality lockdown is not active".into());
    }
    required_tokens(&read(root, "proc/cmdline")?)?;
    if entries(root.join("sys/class/iommu"))?.is_empty() {
        return Err("no active hardware IOMMU".into());
    }
    let groups = entries(root.join("sys/kernel/iommu_groups"))?;
    if groups.is_empty() { return Err("no DMA isolation groups".into()); }
    for group in groups {
        let kind = fs::read_to_string(group.join("type")).map_err(|e| format!("DMA group: {e}"))?;
        if !matches!(kind.trim(), "DMA" | "DMA-FQ") {
            return Err(format!("non-translated DMA group {}", group.display()));
        }
    }
    if read(root, "proc/swaps")?.lines().skip(1).any(|s| !s.trim().is_empty()) {
        return Err("swap is active".into());
    }
    let ima = read(root, "sys/kernel/security/ima/policy")?;
    for hook in ["BPRM_CHECK", "MMAP_CHECK"] {
        if !ima.lines().any(|s| s.split_whitespace().next() == Some("measure") &&
            s.split_whitespace().any(|t| t == format!("func={hook}"))) {
            return Err(format!("IMA does not measure {hook}"));
        }
    }
    let log = fs::metadata(root.join("sys/kernel/security/ima/ascii_runtime_measurements"))
        .map_err(|e| format!("IMA measurement log unavailable: {e}"))?;
    if !log.is_file() { return Err("IMA measurement log is not readable".into()); }
    // Bind root mount to its real dm-verity mapping, not an unrelated dm device.
    let mounts = read(root, "proc/self/mountinfo")?;
    let mount = mounts.lines().find(|s| s.split_whitespace().nth(4) == Some("/"))
        .ok_or("root mount is missing")?;
    let fields: Vec<&str> = mount.split_whitespace().collect();
    if fields.len() < 6 || !fields[5].split(',').any(|s| s == "ro") {
        return Err("root filesystem is writable".into());
    }
    let device = fields[2];
    if !device.chars().all(|c| c.is_ascii_digit() || c == ':') {
        return Err("invalid root device identifier".into());
    }
    let uuid = read(root, &format!("sys/dev/block/{device}/dm/uuid"))?;
    if !uuid.starts_with("CRYPT-VERITY-") { return Err("root is not dm-verity protected".into()); }
    let efivars = root.join("sys/firmware/efi/efivars");
    for (name, expected) in [("SecureBoot", 1), ("SetupMode", 0)] {
        let path = efivars.join(format!("{name}-8be4df61-93ca-11d2-aa0d-00e098032b8c"));
        let data = fs::read(path).map_err(|e| format!("UEFI {name}: {e}"))?;
        if data.len() != 5 || data[4] != expected { return Err(format!("UEFI {name} is unsafe")); }
    }
    Ok(())
}

fn check() -> Result<(), String> {
    local_posture(Path::new("/"))?;
    let status = Command::new("/usr/bin/python3")
        .args(["/usr/local/libexec/examos/keylime_gate.py", "--config", "/etc/examos/keylime-gate.json"])
        .status().map_err(|e| format!("Keylime check could not start: {e}"))?;
    if !status.success() { return Err("Keylime attestation rejected or unavailable".into()); }
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 || !matches!(args[1].as_str(), "--check" | "--watch") {
        eprintln!("usage: examos-runtime-guard --check|--watch"); process::exit(2);
    }
    loop {
        if let Err(reason) = check() {
            eprintln!("EXAMOS_RUNTIME_REJECTED: {reason}"); process::exit(1);
        }
        if args[1] == "--check" { break; }
        thread::sleep(Duration::from_secs(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> PathBuf {
        let root = env::temp_dir().join(format!("examos-guard-{}", process::id()));
        if root.exists() { fs::remove_dir_all(&root).unwrap(); }
        for (p,v) in [
            ("sys/kernel/security/lockdown", "none integrity [confidentiality]"),
            ("proc/cmdline", "iommu.passthrough=0 iommu.strict=1 efi=disable_early_pci_dma"),
            ("sys/class/iommu/dmar0/name", "dmar0"),
            ("sys/kernel/iommu_groups/0/type", "DMA"),
            ("proc/swaps", "Filename Type Size Used Priority\n"),
            ("sys/kernel/security/ima/policy", "measure func=BPRM_CHECK\nmeasure func=MMAP_CHECK mask=MAY_EXEC\n"),
            ("sys/kernel/security/ima/ascii_runtime_measurements", "measurement\n"),
            ("proc/self/mountinfo", "1 0 253:0 / / ro,relatime - ext4 /dev/dm-0 ro\n"),
            ("sys/dev/block/253:0/dm/uuid", "CRYPT-VERITY-root"),
        ] { let path=root.join(p); fs::create_dir_all(path.parent().unwrap()).unwrap(); fs::write(path,v).unwrap(); }
        let dir=root.join("sys/firmware/efi/efivars"); fs::create_dir_all(&dir).unwrap();
        for (n,v) in [("SecureBoot",1),("SetupMode",0)] {
            fs::write(dir.join(format!("{n}-8be4df61-93ca-11d2-aa0d-00e098032b8c")), [7,0,0,0,v]).unwrap();
        }
        root
    }
    #[test] fn rejects_overrides() {
        let good="iommu.passthrough=0 iommu.strict=1 efi=disable_early_pci_dma";
        assert!(required_tokens(good).is_ok());
        for extra in ["iommu.passthrough=1", "iommu.strict=0", "intel_iommu=off", "efi=no_disable_early_pci_dma"] {
            assert!(required_tokens(&format!("{good} {extra}")).is_err());
        }
    }
    #[test] fn rejects_missing_or_weakened_controls() {
        let root=fixture(); assert!(local_posture(&root).is_ok());
        for (path,bad) in [
            ("sys/kernel/security/lockdown","[none] integrity confidentiality"),
            ("sys/kernel/iommu_groups/0/type","identity"),
            ("proc/swaps","Filename Type Size Used Priority\n/dev/sda swap 100 0 -1\n"),
            ("sys/kernel/security/ima/policy","measure func=FILE_CHECK"),
            ("sys/dev/block/253:0/dm/uuid","CRYPT-LUKS-root"),
            ("proc/self/mountinfo","1 0 253:0 / / rw - ext4 /dev/dm-0 rw"),
        ] {
            let p=root.join(path); let old=fs::read(&p).unwrap(); fs::write(&p,bad).unwrap();
            assert!(local_posture(&root).is_err(),"accepted weakened {path}"); fs::write(p,old).unwrap();
        }
        fs::remove_file(root.join("sys/kernel/security/lockdown")).unwrap();
        assert!(local_posture(&root).is_err()); fs::remove_dir_all(root).unwrap();
    }
}
