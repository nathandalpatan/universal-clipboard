// HIST-5 — biometric gate for the History view.
//
// macOS: LocalAuthentication (`LAContext`). We prefer Touch ID
// (`DeviceOwnerAuthenticationWithBiometrics`) and fall back to
// `DeviceOwnerAuthentication` (biometrics-or-password) so password-only Macs and
// Macs without an enrolled fingerprint still work.
//
// Other platforms (Linux / Windows for now): no support. `authenticate` reports
// `supported: false` and the GUI shows History WITHOUT a gate plus a subtle
// "biometric lock unavailable" note — never a fake lock.
//
// Threading: `LAContext` may be created and evaluated off the main thread; the
// framework marshals its own UI to the main queue and invokes the reply block on
// a private queue. We bridge that callback to async by sending the result over a
// `tokio` oneshot and awaiting it in the (async) tauri command.

use serde::Serialize;

/// Result of a biometric attempt, returned to the frontend.
#[derive(Serialize, Clone)]
pub struct AuthResult {
    /// Whether biometric/device-owner auth is available on this platform+device.
    pub supported: bool,
    /// Whether the user successfully authenticated.
    pub success: bool,
    /// Human-readable reason on failure/cancel (e.g. "User canceled").
    pub error: Option<String>,
}

/// Cheap, NON-prompting capability probe. Never shows UI. Used to populate the
/// Settings note and to decide whether History is gated at all.
#[cfg(target_os = "macos")]
pub fn available() -> bool {
    use objc2_local_authentication::{LAContext, LAPolicy};
    // Safe: LAContext::new allocates a fresh context; canEvaluatePolicy never
    // shows UI and is safe from any thread.
    unsafe {
        let context = LAContext::new();
        context
            .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
            .is_ok()
            || context
                .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication)
                .is_ok()
    }
}

#[cfg(not(target_os = "macos"))]
pub fn available() -> bool {
    false
}

type AuthOutcome = (bool, Option<String>);

/// Run the biometric prompt. Async: resolves when the user completes or cancels.
///
/// All AppKit/LocalAuthentication objects (which are `!Send`) are confined to the
/// synchronous `begin_evaluation` helper so the returned future stays `Send` (a
/// tauri command requirement). The `LAContext` is kept alive past this function
/// by moving a retained clone into the reply block, which LocalAuthentication
/// copies and holds until the callback fires.
#[cfg(target_os = "macos")]
pub async fn authenticate(reason: &str) -> AuthResult {
    let (tx, rx) = tokio::sync::oneshot::channel::<AuthOutcome>();
    if !begin_evaluation(reason, tx) {
        return AuthResult {
            supported: false,
            success: false,
            error: None,
        };
    }
    match rx.await {
        Ok((success, error)) => AuthResult {
            supported: true,
            success,
            error: if success { None } else { error },
        },
        Err(_) => AuthResult {
            supported: true,
            success: false,
            error: Some("authentication was interrupted".into()),
        },
    }
}

/// Synchronous LA setup. Returns `false` (dropping `tx`) if no policy can be
/// evaluated; otherwise fires `evaluatePolicy` and returns `true`, with the
/// result delivered later over `tx`.
#[cfg(target_os = "macos")]
fn begin_evaluation(reason: &str, tx: tokio::sync::oneshot::Sender<AuthOutcome>) -> bool {
    use std::sync::Mutex;

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    // Safe: fresh context; policy probing shows no UI.
    let context = unsafe { LAContext::new() };
    let policy = if unsafe {
        context
            .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
            .is_ok()
    } {
        LAPolicy::DeviceOwnerAuthenticationWithBiometrics
    } else if unsafe {
        context
            .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication)
            .is_ok()
    } {
        LAPolicy::DeviceOwnerAuthentication
    } else {
        return false;
    };

    // The reply block is `Fn` per the block ABI but the oneshot Sender is
    // single-use, so guard it behind a take-able slot. The `context` clone is
    // moved in purely to keep the LAContext alive until the callback fires.
    let slot: Mutex<Option<tokio::sync::oneshot::Sender<AuthOutcome>>> = Mutex::new(Some(tx));
    let keep_alive = context.clone();
    let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
        let _keep = &keep_alive;
        let msg = if error.is_null() {
            None
        } else {
            // Safe: non-null NSError provided by LocalAuthentication.
            let err: &NSError = unsafe { &*error };
            Some(err.localizedDescription().to_string())
        };
        if let Ok(mut guard) = slot.lock() {
            if let Some(sender) = guard.take() {
                let _ = sender.send((success.as_bool(), msg));
            }
        }
    });

    let ns_reason = NSString::from_str(reason);
    // Safe: valid context, reason, and block; the framework copies the block.
    unsafe {
        context.evaluatePolicy_localizedReason_reply(policy, &ns_reason, &reply);
    }
    true
}

#[cfg(not(target_os = "macos"))]
pub async fn authenticate(_reason: &str) -> AuthResult {
    AuthResult {
        supported: false,
        success: false,
        error: None,
    }
}
