//! Embeds the icon, the application manifest and VERSIONINFO into the exe.
fn main() {
    println!("cargo:rerun-if-changed=app.rc");
    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rerun-if-changed=../ui/assets/icon.ico");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let var = |key: &str| std::env::var(key).unwrap_or_default();
    let macros = [
        format!("VERSION_MAJOR={}", var("CARGO_PKG_VERSION_MAJOR")),
        format!("VERSION_MINOR={}", var("CARGO_PKG_VERSION_MINOR")),
        format!("VERSION_PATCH={}", var("CARGO_PKG_VERSION_PATCH")),
        format!("FILE_VERSION_STR=\"{}\"", var("CARGO_PKG_VERSION")),
    ];
    // A build without the manifest would silently lose DPI awareness and long paths: fail instead.
    embed_resource::compile("app.rc", &macros)
        .manifest_required()
        .unwrap();
}
