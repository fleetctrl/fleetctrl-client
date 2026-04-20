use anyhow::{anyhow, Context, Result};
use fleetctrl_core::traits::{ProcessOutput, ProcessRunner};
use std::{
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};
use wait_timeout::ChildExt;

#[derive(Debug, Default)]
pub struct CommandProcessRunner;

impl ProcessRunner for CommandProcessRunner {
    fn run(
        &self,
        exe: &str,
        args: &[&str],
        timeout: Duration,
        cwd: Option<&Path>,
    ) -> Result<ProcessOutput> {
        let mut command = Command::new(exe);
        command.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }

        let mut child = command.spawn().with_context(|| format!("failed to spawn {exe}"))?;
        let status = child
            .wait_timeout(timeout)?
            .ok_or_else(|| anyhow!("{exe} timed out after {:?}", timeout))?;
        if status.success() {
            let output = child.wait_with_output()?;
            return Ok(ProcessOutput {
                status_code: output.status.code().unwrap_or_default(),
                stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }

        let output = child.wait_with_output()?;
        Ok(ProcessOutput {
            status_code: output.status.code().unwrap_or_default(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}
