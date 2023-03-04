#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release
use unicorn_engine::unicorn_const::{Arch, Mode, Permission};
use object::{Object,ObjectSection, Architecture, File};
use unicorn_engine::Unicorn;
use eframe::egui;
use std::fs;

// The GUI component of x64emulator


fn main() {
   let native_options = eframe::NativeOptions::default();
   eframe::run_native("x64emulator", native_options, Box::new(|cc| Box::new(EmuGui::new(cc))));
}


#[derive(Default)]
struct EmuGui {
}

impl EmuGui {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self::default()
    }
}

impl eframe::App for EmuGui {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("filler");
        });
    }
}
// Read in files, parse their naming, allocate some stuff in a Unicorn instance.

// Support emulation of functions in object files and executable formats ( non-packed, unvirtualized instructions )

// Allow for new pieces of data to be created and custom register state.

// Emulate any selected function in a binary with a click of a button.

// Optional : Statically determine the calling convention of all functions and produce function signatures.

// Stretch goal : Implement .dmp parser and allow for emulation of a function in a dump file.
