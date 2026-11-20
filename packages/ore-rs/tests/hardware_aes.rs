//! Fails when a build on hardware-AES-capable aarch64 loses `--cfg aes_armv8`,
//! for example because a `RUSTFLAGS` environment variable replaced the
//! workspace's `.cargo/config.toml` rustflags. Without the flag the `aes`
//! crate silently uses its software backend.

#[test]
#[cfg(target_arch = "aarch64")]
fn hardware_aes_is_used_when_the_cpu_has_it() {
    if std::arch::is_aarch64_feature_detected!("aes") {
        assert!(
            ore_rs::hardware_aes(),
            "this CPU has AES, but ore-rs was built without `--cfg aes_armv8`; \
             is RUSTFLAGS overriding .cargo/config.toml?"
        );
    }
}

#[test]
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn hardware_aes_matches_aes_ni() {
    assert_eq!(
        ore_rs::hardware_aes(),
        std::arch::is_x86_feature_detected!("aes")
    );
}
