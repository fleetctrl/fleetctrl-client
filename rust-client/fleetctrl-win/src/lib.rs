mod process;
mod service_control;
mod system;

pub use process::CommandProcessRunner;
pub use service_control::WindowsServiceControl;
pub use system::WindowsSystemInfo;

#[cfg(windows)]
mod registry;
#[cfg(windows)]
mod secrets;

#[cfg(not(windows))]
mod registry;
#[cfg(not(windows))]
mod secrets;

pub use registry::WindowsRegistry;
pub use secrets::DpapiSecretStore;
