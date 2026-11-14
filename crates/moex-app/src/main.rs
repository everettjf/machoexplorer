// Release builds on Windows are GUI-subsystem apps (no console window).
#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

fn main() {
    moex_app::app::run();
}
