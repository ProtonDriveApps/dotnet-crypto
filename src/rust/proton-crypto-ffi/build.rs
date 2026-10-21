use std::env;

fn main() {
    println!("cargo:rerun-if-changed=resources/version.rc");
    println!("cargo:rerun-if-env-changed=CI_PIPELINE_IID");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_windows_version_info();
    }
}

/// Embeds a VERSIONINFO resource into the Windows DLL, using the package version from Cargo.toml.
/// The file version only supports numbers (MAJOR.MINOR.PATCH.BUILD), the product version is the full semver string.
/// BUILD is the GitLab pipeline number ($CI_PIPELINE_IID), 0 for local builds.
fn embed_windows_version_info() {
    let major = env!("CARGO_PKG_VERSION_MAJOR");
    let minor = env!("CARGO_PKG_VERSION_MINOR");
    let patch = env!("CARGO_PKG_VERSION_PATCH");
    let build = match env::var("CI_PIPELINE_IID") {
        Ok(iid) => iid
            .parse::<u16>()
            .unwrap_or_else(|_| panic!("CI_PIPELINE_IID \"{iid}\" does not fit in a Windows file version component (max 65535)")),
        Err(_) => 0,
    };

    let macros = [
        format!("VER_MAJOR={major}"),
        format!("VER_MINOR={minor}"),
        format!("VER_PATCH={patch}"),
        format!("VER_BUILD={build}"),
        format!("VER_FILE_STRING=\"{major}.{minor}.{patch}.{build}\""),
        format!("VER_PRODUCT_STRING=\"{}\"", env!("CARGO_PKG_VERSION")),
    ];
    embed_resource::compile_for_everything("resources/version.rc", &macros)
        .manifest_required()
        .unwrap();
}
