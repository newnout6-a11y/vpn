// The embedded asset directory (`include_dir!`) is only re-read when the crate is rebuilt; files
// added under `assets/` must trigger that rebuild. Locale fragments are `include_str!`ed through
// `LOCALES`, which cargo tracks by itself.
fn main() {
    println!("cargo:rerun-if-changed=assets");
}
