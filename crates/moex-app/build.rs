//! Embeds the application icon into the Windows executable.

fn main() {
    println!("cargo:rerun-if-changed=assets/MachOExplorer.ico");
    #[cfg(windows)]
    {
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            let mut res = winresource::WindowsResource::new();
            res.set_icon("assets/MachOExplorer.ico");
            if let Err(e) = res.compile() {
                // A missing resource compiler should not break the build.
                println!("cargo:warning=could not embed the application icon: {e}");
            }
        }
    }
}
