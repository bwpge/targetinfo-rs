use std::fmt;

use colored::{Color, Colorize};
use sspi::ntlm::AvPair;

pub struct Record {
    target: String,
    av_pairs: Vec<AvPair>,
}

impl Record {
    pub fn new<S: Into<String>>(target: S, av_pairs: Vec<AvPair>) -> Self {
        Self {
            target: target.into(),
            av_pairs,
        }
    }
}

pub struct Output {
    greppable: bool,
    no_color: bool,
}

impl Output {
    pub fn new(greppable: bool, no_color: bool) -> Self {
        Self {
            greppable,
            no_color,
        }
    }

    pub fn error<D: fmt::Display>(&self, msg: D) {
        eprintln!("{} {msg}", "error:".bold().red());
    }

    pub fn warn<D: fmt::Display>(&self, msg: D) {
        eprintln!("{}: {msg}", "warning:".bold().yellow());
    }

    pub fn print_header<D: fmt::Display>(&self, msg: D) {
        if self.greppable {
            return;
        }

        let header = format!("Target: {msg}");
        eprintln!();
        if self.no_color {
            eprintln!("{header}")
        } else {
            eprintln!("{}", header.bold().blue())
        }
    }

    pub fn print(&self, r: Record) {
        if self.greppable {
            self.print_greppable(r);
        } else if self.no_color {
            self.print_plain(r);
        } else {
            self.print_color(r);
        }
    }

    fn print_greppable(&self, r: Record) {
        for item in &r.av_pairs {
            // NOTE: use stdout because greppable format is likely being piped somewhere else
            println!("{}|{}|{}", &r.target, item.id, item.value);
        }
    }

    fn print_color(&self, r: Record) {
        for item in &r.av_pairs {
            let id = format!("0x{:02x}", item.id.to_u16());
            let value_color = if matches!(item.value, sspi::ntlm::AvValue::Utf16(_)) {
                Color::Green
            } else {
                Color::Magenta
            };

            eprintln!(
                "{} {id} {}: {}",
                "[+]".cyan(),
                item.id.to_string().bold().yellow(),
                item.value.to_string().color(value_color)
            );
        }
    }

    fn print_plain(&self, r: Record) {
        for item in &r.av_pairs {
            let id = format!("0x{:02x}", item.id.to_u16());
            eprintln!("[+] {id} {}: {}", item.id, item.value);
        }
    }
}
