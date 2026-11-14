//! `events.jsonl` + `events.1.jsonl` in the data folder: one JSON record per line, a new
//! generation once the current one passes the cap (so the journal stays under twice the cap).
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::record::Record;

/// The current generation.
pub const FILE: &str = "events.jsonl";
/// The previous generation.
pub const PREVIOUS: &str = "events.1.jsonl";
/// Size at which a new generation starts.
pub const CAP_BYTES: u64 = 512 * 1024;

/// The two generations in one folder.
pub struct EventFile {
    current: PathBuf,
    previous: PathBuf,
    cap: u64,
}

impl EventFile {
    pub fn new(dir: &Path, cap: u64) -> Self {
        Self {
            current: dir.join(FILE),
            previous: dir.join(PREVIOUS),
            cap,
        }
    }

    /// Either generation exists (a cleared journal still does: it is not seeded again).
    pub fn exists(&self) -> bool {
        self.current.exists() || self.previous.exists()
    }

    /// Every readable record, oldest first; a damaged line (a write cut by a crash) is skipped.
    pub fn read(&self) -> Vec<Record> {
        [&self.previous, &self.current]
            .into_iter()
            .filter_map(|path| fs::read(path).ok())
            .flat_map(|bytes| {
                String::from_utf8_lossy(&bytes)
                    .lines()
                    .filter_map(|line| serde_json::from_str::<Record>(line).ok())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Appends `record`; `true` when the current generation passed the cap and became the
    /// previous one.
    pub fn append(&self, record: &Record) -> io::Result<bool> {
        let mut line = serde_json::to_vec(record).map_err(io::Error::other)?;
        line.push(b'\n');
        if let Some(parent) = self.current.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&self.current)?;
        // A line cut by a crash must not swallow the next one.
        if !ends_with_newline(&mut file)? {
            line.insert(0, b'\n');
        }
        file.write_all(&line)?;
        let size = file.metadata()?.len();
        drop(file);
        if size < self.cap {
            return Ok(false);
        }
        fs::rename(&self.current, &self.previous)?;
        Ok(true)
    }

    /// Empties the journal: the previous generation deleted, the current one truncated.
    pub fn clear(&self) -> io::Result<()> {
        match fs::remove_file(&self.previous) {
            Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
            _ => {}
        }
        File::create(&self.current).map(drop)
    }
}

fn ends_with_newline(file: &mut File) -> io::Result<bool> {
    if file.metadata()?.len() == 0 {
        return Ok(true);
    }
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    Ok(last[0] == b'\n')
}
