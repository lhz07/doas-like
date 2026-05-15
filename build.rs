// use std::env;
// use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=pam");
    // let sdk_path = std::process::Command::new("xcrun")
    //     .args(["--sdk", "macosx", "--show-sdk-path"])
    //     .output()
    //     .expect("failed to run xcrun");
    // let sdk_path = String::from_utf8(sdk_path.stdout).unwrap();
    // let sdk_path = sdk_path.trim();
    // // The bindgen::Builder is the main entry point
    // // to bindgen, and lets you build up options for
    // // the resulting bindings.
    // let bindings = bindgen::Builder::default()
    //     .clang_args(["-isysroot", sdk_path])
    //     // The input header we would like to generate
    //     // bindings for.
    //     .header("wrapper.h")
    //     // function
    //     .allowlist_function("pam_start")
    //     .allowlist_function("pam_set_item")
    //     .allowlist_function("pam_authenticate")
    //     .allowlist_function("pam_acct_mgmt")
    //     .allowlist_function("pam_chauthtok")
    //     .allowlist_function("pam_close_session")
    //     .allowlist_function("pam_strerror")
    //     .allowlist_function("pam_setcred")
    //     .allowlist_function("pam_end")
    //     .allowlist_function("readpassphrase")
    //     .allowlist_function("clock_gettime")
    //     .allowlist_function("fstat")
    //     .allowlist_function("futimens")
    //     .allowlist_function("proc_pidinfo")
    //     // var
    //     .allowlist_var("PAM_SUCCESS")
    //     .allowlist_var("NGROUPS_MAX")
    //     .allowlist_var("UID_MAX")
    //     .allowlist_var("GID_MAX")
    //     .allowlist_var("PAM_CONV_ERR")
    //     .allowlist_var("PAM_MAX_RESP_SIZE")
    //     .allowlist_var("RPP_ECHO_OFF")
    //     .allowlist_var("RPP_ECHO_ON")
    //     .allowlist_var("RPP_REQUIRE_TTY")
    //     .allowlist_var("PAM_PROMPT_ECHO_OFF")
    //     .allowlist_var("PAM_PROMPT_ECHO_ON")
    //     .allowlist_var("PAM_ERROR_MSG")
    //     .allowlist_var("PAM_TEXT_INFO")
    //     .allowlist_var("PAM_RUSER")
    //     .allowlist_var("PAM_NEW_AUTHTOK_REQD")
    //     .allowlist_var("PAM_CHANGE_EXPIRED_AUTHTOK")
    //     .allowlist_var("PAM_USER")
    //     .allowlist_var("PAM_REINITIALIZE_CRED")
    //     .allowlist_var("PAM_DELETE_CRED")
    //     .allowlist_var("PAM_SILENT")
    //     .allowlist_var("PROC_PIDTBSDINFO")
    //     // type
    //     .allowlist_type("pam_handle_t")
    //     .allowlist_type("pam_handle")
    //     .allowlist_type("pam_conv")
    //     .allowlist_type("pam_message")
    //     .allowlist_type("pam_response")
    //     .allowlist_type("proc_bsdinfo")
    //     .allowlist_type("stat")
    //     .allowlist_type("timespec")
    //     // Tell cargo to invalidate the built crate whenever any of the
    //     // included header files changed.
    //     .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
    //     // Finish the builder and generate the bindings.
    //     .generate()
    //     // Unwrap the Result and panic on failure.
    //     .expect("Unable to generate bindings");
    //
    // // Write the bindings to the $OUT_DIR/bindings.rs file.
    // let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    // bindings
    //     .write_to_file(out_path.join("bindings.rs"))
    //     .expect("Couldn't write bindings!");
}
