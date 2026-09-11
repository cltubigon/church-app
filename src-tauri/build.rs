fn main() {
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg=/MANIFESTDEPENDENCY:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'"
        );

        let windows = tauri_build::WindowsAttributes::new_without_app_manifest();
        let attributes = tauri_build::Attributes::new().windows_attributes(windows);
        tauri_build::try_build(attributes).expect("the Tauri build script should succeed");
    }

    #[cfg(not(target_os = "windows"))]
    tauri_build::build();
}
