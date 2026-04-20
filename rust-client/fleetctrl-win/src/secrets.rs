#[cfg(windows)]
mod imp {
    use anyhow::{Context, Result};
    use fleetctrl_core::traits::SecretStore;
    use std::{fs, path::Path};
    use windows_dpapi::{decrypt_data, encrypt_data, Scope};

    #[derive(Debug, Default)]
    pub struct DpapiSecretStore;

    impl SecretStore for DpapiSecretStore {
        fn save_machine_secret(&self, path: &Path, bytes: &[u8]) -> Result<()> {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let encrypted = encrypt_data(bytes, Scope::Machine, None).context("failed to encrypt secret")?;
            fs::write(path, encrypted)?;
            Ok(())
        }

        fn load_machine_secret(&self, path: &Path) -> Result<Vec<u8>> {
            let bytes = fs::read(path)?;
            Ok(decrypt_data(&bytes, Scope::Machine, None).context("failed to decrypt secret")?)
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use anyhow::{anyhow, Result};
    use fleetctrl_core::traits::SecretStore;
    use std::path::Path;

    #[derive(Debug, Default)]
    pub struct DpapiSecretStore;

    impl SecretStore for DpapiSecretStore {
        fn save_machine_secret(&self, _path: &Path, _bytes: &[u8]) -> Result<()> {
            Err(anyhow!("DPAPI is only available on Windows"))
        }
        fn load_machine_secret(&self, _path: &Path) -> Result<Vec<u8>> {
            Err(anyhow!("DPAPI is only available on Windows"))
        }
    }
}

pub use imp::DpapiSecretStore;
