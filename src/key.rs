use zeroize::Zeroizing;

#[cfg(not(windows))]
pub fn load() -> Result<Zeroizing<Vec<u8>>, &'static str> {
    Err("windows_required")
}

#[cfg(windows)]
pub fn load() -> Result<Zeroizing<Vec<u8>>, &'static str> {
    use std::io::Read;
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };
    let root = std::env::var_os("LOCALAPPDATA").ok_or("key_unavailable")?;
    let path = std::path::PathBuf::from(root)
        .join("com.freshthread.desktop")
        .join("installation.key");
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| "key_unavailable")?;
    if !path.is_absolute()
        || !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > 4096
    {
        return Err("key_unavailable");
    }
    let mut encrypted = Zeroizing::new(Vec::new());
    std::fs::File::open(path)
        .and_then(|f| f.take(4097).read_to_end(&mut encrypted))
        .map_err(|_| "key_unavailable")?;
    if encrypted.len() as u64 != metadata.len() {
        return Err("key_unavailable");
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: encrypted.len() as u32,
        pbData: encrypted.as_mut_ptr(),
    };
    let entropy_bytes = b"FreshThread/installation-hmac/v1";
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: entropy_bytes.len() as u32,
        pbData: entropy_bytes.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: input and entropy outlive the call; output is owned by LocalBlob.
    unsafe {
        CryptUnprotectData(
            &raw const input,
            None,
            Some(&raw const entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    }
    .map_err(|_| "key_unavailable")?;
    let output = LocalBlob(output);
    if output.0.pbData.is_null() || output.0.cbData != 32 {
        return Err("key_unavailable");
    }
    // SAFETY: DPAPI allocated exactly the reported length; the guard owns it.
    Ok(Zeroizing::new(
        unsafe { std::slice::from_raw_parts(output.0.pbData, 32) }.to_vec(),
    ))
}

#[cfg(windows)]
struct LocalBlob(windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB);
#[cfg(windows)]
impl Drop for LocalBlob {
    fn drop(&mut self) {
        use windows::Win32::Foundation::{HLOCAL, LocalFree};
        use zeroize::Zeroize;
        if !self.0.pbData.is_null() {
            // SAFETY: this guard exclusively owns the live DPAPI allocation.
            unsafe { std::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize) }
                .zeroize();
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0.pbData.cast()))) };
        }
    }
}
