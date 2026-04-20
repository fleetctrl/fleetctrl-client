use anyhow::Result;
use fleetctrl_core::traits::{ProcessRunner, ServiceControl};
use std::{path::Path, time::Duration};

use crate::CommandProcessRunner;

#[derive(Debug, Default)]
pub struct WindowsServiceControl {
    runner: CommandProcessRunner,
}

impl WindowsServiceControl {
    pub fn new() -> Self {
        Self {
            runner: CommandProcessRunner,
        }
    }
}

impl ServiceControl for WindowsServiceControl {
    fn install_service(&self, service_name: &str, display_name: &str, exe_path: &Path) -> Result<()> {
        let bin_path = format!(r#"binPath= "{}""#, exe_path.display());
        let display = format!(r#"DisplayName= "{}""#, display_name);
        self.runner.run(
            "sc.exe",
            &[
                "create",
                service_name,
                &bin_path,
                &display,
                "start= auto",
                r#"obj= "LocalSystem""#,
            ],
            Duration::from_secs(30),
            None,
        )?;
        Ok(())
    }

    fn remove_service(&self, service_name: &str) -> Result<()> {
        let _ = self.stop_service(service_name);
        self.runner.run("sc.exe", &["delete", service_name], Duration::from_secs(30), None)?;
        Ok(())
    }

    fn start_service(&self, service_name: &str) -> Result<()> {
        self.runner.run("sc.exe", &["start", service_name], Duration::from_secs(30), None)?;
        Ok(())
    }

    fn stop_service(&self, service_name: &str) -> Result<()> {
        self.runner.run("sc.exe", &["stop", service_name], Duration::from_secs(30), None)?;
        Ok(())
    }

    fn service_exists(&self, service_name: &str) -> Result<bool> {
        let output = self
            .runner
            .run("sc.exe", &["query", service_name], Duration::from_secs(15), None)?;
        Ok(!output.stdout.contains("FAILED 1060") && !output.stderr.contains("FAILED 1060"))
    }

    fn is_running(&self, service_name: &str) -> Result<bool> {
        let output = self
            .runner
            .run("sc.exe", &["query", service_name], Duration::from_secs(15), None)?;
        Ok(output.stdout.contains("RUNNING"))
    }
}
