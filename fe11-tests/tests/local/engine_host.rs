// SPDX-License-Identifier: Apache-2.0
//! Optional engine isolation in a fresh Linux process with an actual host libcrypto.
use fe11::*;
use libloading::{
    os::unix::{Library as UnixLibrary, RTLD_GLOBAL, RTLD_NOW},
    Library,
};
use sha2::{Digest, Sha256};
use std::{
    ffi::{c_char, c_int, c_ulong, c_void},
    fs,
    path::PathBuf,
    ptr,
};

type Init = unsafe extern "C" fn(u64, *const c_void) -> c_int;
type Fetch = unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> *mut c_void;
type Free = unsafe extern "C" fn(*mut c_void);
type GetError = unsafe extern "C" fn() -> c_ulong;
type NewError = unsafe extern "C" fn();
type SetError = unsafe extern "C" fn(c_int, c_int, *const c_char, ...);

fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    assert!(text.len() <= 32768, "public fixture field bound");
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |value: u8| match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                b'A'..=b'F' => value - b'A' + 10,
                _ => panic!("hexadecimal public fixture"),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

fn image(path_name: &str, digest_name: &str) -> (PathBuf, [u8; 32]) {
    let path = PathBuf::from(std::env::var_os(path_name).expect("explicit image path"));
    assert!(path.is_absolute());
    let expected: [u8; 32] = hex(&std::env::var(digest_name).expect("explicit digest"))
        .try_into()
        .expect("SHA256 width");
    let metadata = fs::metadata(&path).expect("image metadata");
    assert!(metadata.is_file() && metadata.len() <= 32 * 1024 * 1024);
    let actual: [u8; 32] = Sha256::digest(fs::read(&path).expect("image bytes")).into();
    assert_eq!(actual, expected, "selected image identity");
    (path, expected)
}

struct Host {
    fetch: Fetch,
    free: Free,
    get_error: GetError,
    new_error: NewError,
    set_error: SetError,
}
impl Host {
    fn load(path: &PathBuf) -> Self {
        // SAFETY: this explicit digest-checked OpenSSL3 image is trusted native
        // code. Global loading deliberately represents the hosting application.
        let loaded = unsafe { UnixLibrary::open(Some(path), RTLD_NOW | RTLD_GLOBAL) }
            .expect("load exact host image");
        // Keep host code present for the entire isolated test process, including
        // any destructor. No other test is run in this invocation.
        let library: &'static Library = Box::leak(Box::new(loaded.into()));
        // SAFETY: the symbols below use their public OpenSSL3 C ABI. The library
        // is retained for process lifetime; no symbol can outlive its image.
        let (init, fetch, free, get_error, new_error, set_error) = unsafe {
            (
                *library
                    .get::<Init>(b"OPENSSL_init_crypto\0")
                    .expect("host initialization"),
                *library.get::<Fetch>(b"EVP_MD_fetch\0").expect("host fetch"),
                *library
                    .get::<Free>(b"EVP_MD_free\0")
                    .expect("host digest release"),
                *library
                    .get::<GetError>(b"ERR_get_error\0")
                    .expect("host error read"),
                *library
                    .get::<NewError>(b"ERR_new\0")
                    .expect("host error entry"),
                *library
                    .get::<SetError>(b"ERR_set_error\0")
                    .expect("host error value"),
            )
        };
        // SAFETY: LOAD_CONFIG is a public flag; NULL settings select the supplied
        // process configuration. No application pointers are retained.
        assert_eq!(unsafe { init(0x40, ptr::null()) }, 1);
        Self {
            fetch,
            free,
            get_error,
            new_error,
            set_error,
        }
    }
    fn denied(&self) {
        // SAFETY: default libctx, terminated algorithm name, NULL properties.
        let md = unsafe { (self.fetch)(ptr::null_mut(), b"SHA256\0".as_ptr().cast(), ptr::null()) };
        if !md.is_null() {
            // SAFETY: fetch returned a live owned EVP_MD and no other user holds it.
            unsafe { (self.free)(md) };
            panic!("host property policy unexpectedly allowed SHA256");
        }
    }
    fn drain(&self) -> Vec<c_ulong> {
        let mut errors = Vec::new();
        for _ in 0..32 {
            // SAFETY: thread-local OpenSSL error queue has no borrowed arguments.
            let value = unsafe { (self.get_error)() };
            if value == 0 {
                return errors;
            }
            errors.push(value);
        }
        panic!("bounded host error queue did not terminate");
    }
    fn seed(&self) {
        for reason in [101, 202, 303] {
            // SAFETY: append a public user-library diagnostic on this thread.
            // NULL format means no formatted data and no variadic arguments.
            unsafe {
                (self.new_error)();
                (self.set_error)(128, reason, ptr::null());
            }
        }
    }
}

fn verify(engine: &VerifyEngine, fixture: &str, expected: Verification) {
    let fields: Vec<_> = fixture.lines().collect();
    assert_eq!(fields.len(), 4);
    let algorithm = PqcAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44);
    let public = PqcPublicKey::from_raw(algorithm, &hex(fields[0])).expect("public ML-DSA key");
    let message = hex(fields[1]);
    let parameters = PqcSignatureParameters::pure(&hex(fields[2]), PqcHedging::Preferred)
        .expect("exact published context");
    let signature = PqcSignature::from_bytes(algorithm, &hex(fields[3])).expect("signature width");
    let actual = public
        .verify(
            engine,
            &message,
            &signature,
            &parameters,
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: message.len(),
            },
        )
        .expect("public verification call");
    assert_eq!(actual, expected);
}

/// Run only in an isolated process with explicit, hash-checked native artifacts.
#[test]
#[ignore = "requires explicit host libcrypto, verify-engine and isolated OpenSSL configuration"]
fn host_context_isolation() {
    let (host_path, _) = image("FE11_PUBLIC_HOST_CRYPTO", "FE11_PUBLIC_HOST_CRYPTO_SHA256");
    let (engine_path, engine_digest) = image(
        "FE11_PUBLIC_VERIFY_ENGINE",
        "FE11_PUBLIC_VERIFY_ENGINE_SHA256",
    );
    assert_ne!(
        fs::canonicalize(&host_path).unwrap(),
        fs::canonicalize(&engine_path).unwrap()
    );
    let config = PathBuf::from(std::env::var_os("OPENSSL_CONF").expect("host policy path"));
    assert!(config.is_absolute());
    assert_eq!(fs::read_to_string(config).expect("host policy bytes"),
        "openssl_conf = host_init\n[host_init]\nalg_section = host_properties\n[host_properties]\ndefault_properties = provider=provider_that_is_not_loaded\n");
    let host = Host::load(&host_path);
    host.denied();
    assert!(
        !host.drain().is_empty(),
        "denied fetch reports a native error"
    );
    host.seed();
    let expected = host.drain();
    assert_eq!(expected.len(), 3);
    assert!(expected[0] != expected[1] && expected[1] != expected[2] && expected[0] != expected[2]);
    host.seed();
    let engine = VerifyEngine::builder(
        engine_path,
        ModuleIntegrity::Sha256 {
            expected: engine_digest,
            on_mismatch: ModuleDigestMismatch::Refuse,
        },
    )
    .open()
    .expect("load isolated optional engine");
    verify(
        &engine,
        include_str!("../vectors/engine-host/valid.txt"),
        Verification::Valid,
    );
    verify(
        &engine,
        include_str!("../vectors/engine-host/invalid.txt"),
        Verification::Invalid,
    );
    drop(engine);
    assert_eq!(
        host.drain(),
        expected,
        "engine must preserve the host error queue"
    );
    host.denied();
    assert!(!host.drain().is_empty(), "host denial remains effective");
}
