// HIST-7 — exclude the GUI window from screen capture / screen sharing.
//
// Platform matrix:
//   * macOS   : NSWindow.sharingType = .none  (fully enforced by WindowServer;
//               the window is omitted from screenshots, ScreenCaptureKit, and
//               screen sharing).
//   * Windows : SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)
//               (cfg-gated, compile-checked only on this branch — no Windows
//               host in CI).
//   * Linux / other : not portably enforceable (X11 has no such primitive and
//               Wayland capture policy is compositor-specific), so this is a
//               documented no-op. See README.
//
// The default is ON (applied at window creation in `main.rs`); a Settings toggle
// re-applies it live via the `set_capture_protection` command without a restart.

/// Apply (or clear) capture protection on the given window. Returns `Ok(())`
/// on platforms where it is a documented no-op.
pub fn apply(window: &tauri::WebviewWindow, enabled: bool) -> Result<(), String> {
    apply_impl(window, enabled)
}

#[cfg(target_os = "macos")]
fn apply_impl(window: &tauri::WebviewWindow, enabled: bool) -> Result<(), String> {
    // All AppKit window mutation must happen on the main thread. `window_handle`
    // and `setSharingType:` are therefore run inside `run_on_main_thread`.
    let win = window.clone();
    window
        .run_on_main_thread(move || {
            use objc2_app_kit::{NSView, NSWindowSharingType};
            use raw_window_handle::{HasWindowHandle, RawWindowHandle};

            let Ok(handle) = win.window_handle() else {
                return;
            };
            if let RawWindowHandle::AppKit(h) = handle.as_raw() {
                // Safe: we are on the main thread, and `ns_view` points at a live
                // NSView owned by the window for as long as the window exists.
                unsafe {
                    let view: &NSView = h.ns_view.cast().as_ref();
                    if let Some(ns_window) = view.window() {
                        let sharing = if enabled {
                            NSWindowSharingType::None
                        } else {
                            NSWindowSharingType::ReadOnly
                        };
                        ns_window.setSharingType(sharing);
                    }
                }
            }
        })
        .map_err(|e| e.to_string())
}

#[cfg(target_os = "windows")]
fn apply_impl(window: &tauri::WebviewWindow, enabled: bool) -> Result<(), String> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_NONE,
    };

    let handle = window.window_handle().map_err(|e| e.to_string())?;
    if let RawWindowHandle::Win32(h) = handle.as_raw() {
        let hwnd = HWND(h.hwnd.get() as *mut core::ffi::c_void);
        let affinity = if enabled {
            WDA_EXCLUDEFROMCAPTURE
        } else {
            WDA_NONE
        };
        // Safe: `hwnd` is a live top-level window handle owned by this process.
        unsafe {
            SetWindowDisplayAffinity(hwnd, affinity).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn apply_impl(_window: &tauri::WebviewWindow, _enabled: bool) -> Result<(), String> {
    // Not portably enforceable on Linux; documented no-op.
    Ok(())
}
