use bitmask_enum::bitmask;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use sysinfo::{System, SystemExt};

/// Various different system combinations available for constructing a HWID.
#[bitmask(u8)]
pub enum Combinations {
    /// Total amount of memory present in the system, in bytes.
    TotalMemBytes,
    /// Computer host name, this is usually "DESKTOP-..." on Windows, and user-defined on Linux.
    HostName,
    /// Current OS Version.
    OSVersion,
    /// Current OS Kernel Version.
    KernelVersion,
    /// The amount of cores present on the hosts CPU.
    CoresCount,
}

/// Returns the combined Hardware ID as an encrypted String.
/// The IDs are a combination of identifiers specified through the `combinations` paramter.
/// The HWID is encrypted using 256-bit Base64, with the key specified through the `encryption`
/// parameter.
pub fn get_hwid(combinations: Combinations, encryption: &str) -> Option<String> {
    let mut combination = String::new();
    let mut sys = System::new_all();
    let crypt = new_magic_crypt!(encryption, 256);
    sys.refresh_all();
    if combinations.contains(Combinations::TotalMemBytes) {
        combination.push_str(&sys.total_memory().to_string());
    }

    if combinations.contains(Combinations::HostName) {
        combination.push_str(&sys.host_name()?);
    }

    if combinations.contains(Combinations::OSVersion) {
        combination.push_str(&sys.os_version()?);
    }

    if combinations.contains(Combinations::KernelVersion) {
        combination.push_str(&sys.kernel_version()?);
    }

    if combinations.contains(Combinations::CoresCount) {
        combination.push_str(&sys.cpus().len().to_string());
    }

    Some(crypt.encrypt_str_to_base64(combination))
}
