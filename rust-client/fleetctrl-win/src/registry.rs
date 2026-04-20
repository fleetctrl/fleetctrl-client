#[cfg(windows)]
mod imp {
    use anyhow::Result;
    use fleetctrl_core::traits::RegistryStore;
    use winreg::{enums::*, RegKey};

    #[derive(Debug, Default)]
    pub struct WindowsRegistry;

    impl WindowsRegistry {
        fn open_or_create(&self, path: &str) -> Result<RegKey> {
            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            let (key, _) = hklm.create_subkey(path)?;
            Ok(key)
        }
    }

    impl RegistryStore for WindowsRegistry {
        fn get_string(&self, path: &str, name: &str) -> Result<Option<String>> {
            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            match hklm.open_subkey_with_flags(path, KEY_QUERY_VALUE) {
                Ok(key) => Ok(key.get_value(name).ok()),
                Err(_) => Ok(None),
            }
        }

        fn get_u32(&self, path: &str, name: &str) -> Result<Option<u32>> {
            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            match hklm.open_subkey_with_flags(path, KEY_QUERY_VALUE) {
                Ok(key) => Ok(key.get_value(name).ok()),
                Err(_) => Ok(None),
            }
        }

        fn set_string(&self, path: &str, name: &str, value: &str) -> Result<()> {
            self.open_or_create(path)?.set_value(name, &value)?;
            Ok(())
        }

        fn set_u32(&self, path: &str, name: &str, value: u32) -> Result<()> {
            self.open_or_create(path)?.set_value(name, &value)?;
            Ok(())
        }

        fn delete_value(&self, path: &str, name: &str) -> Result<()> {
            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            if let Ok(key) = hklm.open_subkey_with_flags(path, KEY_SET_VALUE) {
                let _ = key.delete_value(name);
            }
            Ok(())
        }

        fn ensure_key(&self, path: &str) -> Result<()> {
            let _ = self.open_or_create(path)?;
            Ok(())
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use anyhow::{anyhow, Result};
    use fleetctrl_core::traits::RegistryStore;

    #[derive(Debug, Default)]
    pub struct WindowsRegistry;

    impl RegistryStore for WindowsRegistry {
        fn get_string(&self, _path: &str, _name: &str) -> Result<Option<String>> {
            Err(anyhow!("Windows registry is only available on Windows"))
        }
        fn get_u32(&self, _path: &str, _name: &str) -> Result<Option<u32>> {
            Err(anyhow!("Windows registry is only available on Windows"))
        }
        fn set_string(&self, _path: &str, _name: &str, _value: &str) -> Result<()> {
            Err(anyhow!("Windows registry is only available on Windows"))
        }
        fn set_u32(&self, _path: &str, _name: &str, _value: u32) -> Result<()> {
            Err(anyhow!("Windows registry is only available on Windows"))
        }
        fn delete_value(&self, _path: &str, _name: &str) -> Result<()> {
            Err(anyhow!("Windows registry is only available on Windows"))
        }
        fn ensure_key(&self, _path: &str) -> Result<()> {
            Err(anyhow!("Windows registry is only available on Windows"))
        }
    }
}

pub use imp::WindowsRegistry;
