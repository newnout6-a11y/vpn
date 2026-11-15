//! Minimal YAML reader for Clash documents: a string-only tree built from `saphyr-parser` events.
//!
//! Scalars keep their source text (no type resolution), so `password: 0012345` stays `0012345`
//! and `short-id: 0123` keeps its leading zero; the old hand-rolled reader turned both into
//! numbers. Only the root `proxies` list is materialised, item by item; every other section is
//! skipped event by event, so a provider file with 100k routing rules costs one pass and no tree.
use std::collections::{HashMap, HashSet};

use saphyr_parser::{Event, Parser, ScalarStyle, StrInput};

/// Nesting deeper than this is not a proxy entry; the limit also bounds recursion.
const MAX_DEPTH: usize = 32;
/// Approximate bytes materialised over the whole read, alias copies included: stops "billion
/// laughs" bombs, also those made of one long scalar aliased many times. 5000 real entries
/// cost about 15 MB.
const MAX_BYTES: usize = 64 << 20;
/// Cost of one node besides its text (the enum, its slot in the parent, the allocation).
const NODE_BYTES: usize = 64;

/// A YAML node with every scalar kept as text.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Node {
    /// `plain` is false for quoted and block scalars: only a plain `~`/`null`/empty is "absent".
    Scalar {
        text: String,
        plain: bool,
    },
    Seq(Vec<Node>),
    /// Pairs in source order; non-scalar keys are dropped, merge keys (`<<`) are resolved.
    Map(Vec<(String, Node)>),
}

/// Why the document could not be read (English, for diagnostics only).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(super) enum YamlError {
    #[error("YAML syntax error at line {line}: {msg}")]
    Syntax { line: usize, msg: String },
    #[error("YAML nesting is deeper than {MAX_DEPTH} levels")]
    TooDeep,
    #[error("YAML document is too large once aliases are expanded")]
    TooLarge,
    #[error("YAML alias refers to an unknown anchor")]
    UnknownAlias,
}

/// Result of [`read_proxies`]: whether a root `proxies` list was entered, and what stopped it early.
pub(super) struct ReadOutcome {
    pub found: bool,
    pub error: Option<YamlError>,
}

/// Feeds each item of the first root-level `proxies` list to `visit` (which returns `false` to
/// stop). Items read before an error are kept by the caller; reading stops after the list.
pub(super) fn read_proxies(text: &str, mut visit: impl FnMut(Node) -> bool) -> ReadOutcome {
    let mut reader = Reader {
        parser: Parser::new_from_str(text),
        anchors: HashMap::new(),
        used: 0,
        found: false,
    };
    let error = reader.run(&mut visit).err();
    ReadOutcome {
        found: reader.found,
        error,
    }
}

/// The value of the root-level `key` of the first document that has one, as a tree; every other
/// section is skipped event by event (anchors in them stay usable).
pub(super) fn read_root(text: &str, key: &str) -> Result<Option<Node>, YamlError> {
    let mut reader = Reader {
        parser: Parser::new_from_str(text),
        anchors: HashMap::new(),
        used: 0,
        found: false,
    };
    loop {
        match reader.next()? {
            Event::StreamEnd => return Ok(None),
            Event::MappingStart(..) => {
                if let Some(node) = reader.root_value(key)? {
                    return Ok(Some(node));
                }
            }
            ev @ (Event::Scalar(..) | Event::SequenceStart(..)) => reader.skip(ev)?,
            _ => {}
        }
    }
}

struct Reader<'a> {
    parser: Parser<'a, StrInput<'a>>,
    /// Anchored nodes with their cost in bytes (the cost of each alias copy).
    anchors: HashMap<usize, (Node, usize)>,
    used: usize,
    found: bool,
}

impl<'a> Reader<'a> {
    fn next(&mut self) -> Result<Event<'a>, YamlError> {
        match self.parser.next_event() {
            Some(Ok((event, _))) => Ok(event),
            Some(Err(e)) => Err(YamlError::Syntax {
                line: e.marker().line(),
                msg: e.info().to_owned(),
            }),
            None => Ok(Event::StreamEnd),
        }
    }

    fn run(&mut self, visit: &mut dyn FnMut(Node) -> bool) -> Result<(), YamlError> {
        loop {
            match self.next()? {
                Event::StreamEnd => return Ok(()),
                // A root mapping without `proxies` lets the next document try.
                Event::MappingStart(..) if self.root_mapping(visit)? => return Ok(()),
                ev @ (Event::Scalar(..) | Event::SequenceStart(..)) => self.skip(ev)?,
                _ => {}
            }
        }
    }

    /// Walks one document's root mapping; `true` once its `proxies` value was consumed.
    fn root_mapping(&mut self, visit: &mut dyn FnMut(Node) -> bool) -> Result<bool, YamlError> {
        loop {
            let ev = self.next()?;
            if matches!(ev, Event::MappingEnd) {
                return Ok(false);
            }
            let is_proxies =
                matches!(self.node(ev, 1)?, Node::Scalar { ref text, .. } if text == "proxies");
            let value = self.next()?;
            if !is_proxies {
                self.skip(value)?;
                continue;
            }
            match value {
                Event::SequenceStart(..) => {
                    self.found = true;
                    loop {
                        let ev = self.next()?;
                        if matches!(ev, Event::SequenceEnd) {
                            return Ok(true);
                        }
                        let item = self.node(ev, 1)?;
                        if !visit(item) {
                            return Ok(true);
                        }
                    }
                }
                ev => match self.node(ev, 1)? {
                    Node::Seq(items) => {
                        self.found = true;
                        for item in items {
                            if !visit(item) {
                                break;
                            }
                        }
                        return Ok(true);
                    }
                    // `proxies:` with no items is still a Clash document, just an empty one.
                    node if node.is_null() => {
                        self.found = true;
                        return Ok(true);
                    }
                    _ => {}
                },
            }
        }
    }

    /// Walks one document's root mapping for `key`; its value as a tree, `None` when the mapping
    /// ended without it.
    fn root_value(&mut self, key: &str) -> Result<Option<Node>, YamlError> {
        loop {
            let ev = self.next()?;
            if matches!(ev, Event::MappingEnd) {
                return Ok(None);
            }
            let is_key = matches!(self.node(ev, 1)?, Node::Scalar { ref text, .. } if text == key);
            let value = self.next()?;
            if is_key {
                return self.node(value, 1).map(Some);
            }
            self.skip(value)?;
        }
    }

    /// Builds the node that starts with `ev`; anchored nodes are remembered for later aliases.
    fn node(&mut self, ev: Event<'a>, depth: usize) -> Result<Node, YamlError> {
        if depth > MAX_DEPTH {
            return Err(YamlError::TooDeep);
        }
        let before = self.used;
        spend(&mut self.used, NODE_BYTES)?;
        let (node, anchor) = match ev {
            Event::Scalar(text, style, anchor, _) => {
                spend(&mut self.used, text.len())?;
                let plain = style == ScalarStyle::Plain;
                let text = text.into_owned();
                (Node::Scalar { text, plain }, anchor)
            }
            Event::SequenceStart(anchor, _) => {
                let mut items = Vec::new();
                loop {
                    let ev = self.next()?;
                    if matches!(ev, Event::SequenceEnd) {
                        break;
                    }
                    items.push(self.node(ev, depth + 1)?);
                }
                (Node::Seq(items), anchor)
            }
            Event::MappingStart(anchor, _) => {
                let mut pairs = Vec::new();
                let mut merges = Vec::new();
                loop {
                    let ev = self.next()?;
                    if matches!(ev, Event::MappingEnd) {
                        break;
                    }
                    let key = self.node(ev, depth + 1)?;
                    let value_ev = self.next()?;
                    let value = self.node(value_ev, depth + 1)?;
                    match key {
                        Node::Scalar { text, plain: true } if text == "<<" => merges.push(value),
                        Node::Scalar { text, .. } => pairs.push((text, value)),
                        _ => {}
                    }
                }
                merge_into(&mut pairs, merges);
                (Node::Map(pairs), anchor)
            }
            Event::Alias(id) => {
                let (node, cost) = self.anchors.get(&id).ok_or(YamlError::UnknownAlias)?;
                // Paid before the copy is made.
                spend(&mut self.used, *cost)?;
                (node.clone(), 0)
            }
            _ => {
                return Err(YamlError::Syntax {
                    line: 0,
                    msg: "unexpected event".to_owned(),
                });
            }
        };
        if anchor != 0 {
            self.anchors
                .insert(anchor, (node.clone(), self.used - before));
        }
        Ok(node)
    }

    /// Skips the node that starts with `ev` without building it, except anchored sub-nodes,
    /// which a later alias inside `proxies` may still refer to.
    fn skip(&mut self, mut ev: Event<'a>) -> Result<(), YamlError> {
        let mut depth = 0usize;
        loop {
            match ev {
                Event::Scalar(_, _, anchor, _)
                | Event::SequenceStart(anchor, _)
                | Event::MappingStart(anchor, _)
                    if anchor != 0 =>
                {
                    self.node(ev, 1)?;
                }
                Event::SequenceStart(..) | Event::MappingStart(..) => depth += 1,
                Event::SequenceEnd | Event::MappingEnd => depth = depth.saturating_sub(1),
                // `next` reports a finished stream as StreamEnd forever: never spin on it.
                Event::StreamEnd if depth > 0 => {
                    return Err(YamlError::Syntax {
                        line: 0,
                        msg: "unexpected end of input".to_owned(),
                    });
                }
                _ => {}
            }
            if depth == 0 {
                return Ok(());
            }
            ev = self.next()?;
        }
    }
}

/// Adds `bytes` to the running cost of the read; past [`MAX_BYTES`] the read stops.
fn spend(used: &mut usize, bytes: usize) -> Result<(), YamlError> {
    *used = used.saturating_add(bytes);
    if *used > MAX_BYTES {
        Err(YamlError::TooLarge)
    } else {
        Ok(())
    }
}

/// YAML 1.1 merge keys (`<<: *base`, `<<: [*a, *b]`): explicit keys win, then earlier merges.
/// The key set keeps a merged map with many keys linear, not quadratic.
fn merge_into(pairs: &mut Vec<(String, Node)>, merges: Vec<Node>) {
    if merges.is_empty() {
        return;
    }
    let mut seen: HashSet<String> = pairs.iter().map(|(k, _)| k.clone()).collect();
    for merge in merges {
        let maps = match merge {
            Node::Seq(items) => items,
            map => vec![map],
        };
        for map in maps {
            if let Node::Map(extra) = map {
                for (key, value) in extra {
                    if seen.insert(key.clone()) {
                        pairs.push((key, value));
                    }
                }
            }
        }
    }
}

impl Node {
    /// True for a plain `~`, `null` or empty scalar.
    pub(super) fn is_null(&self) -> bool {
        matches!(self, Node::Scalar { text, plain: true } if is_null_text(text))
    }

    /// Scalar text; quoted text is kept verbatim (a password may start with a space, plain
    /// scalars are trimmed by YAML itself). `None` for nulls, blank text and collections.
    pub(super) fn as_str(&self) -> Option<&str> {
        match self {
            Node::Scalar { text, plain } => {
                let absent = text.trim().is_empty() || (*plain && is_null_text(text));
                (!absent).then_some(text.as_str())
            }
            _ => None,
        }
    }

    /// YAML / Clash booleans: `true/false/yes/no/on/off/1/0`, any case.
    pub(super) fn as_bool(&self) -> Option<bool> {
        match self.as_str()?.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" | "1" => Some(true),
            "false" | "no" | "off" | "0" => Some(false),
            _ => None,
        }
    }

    /// A sequence of scalars, a `[a, b]` string or a comma-separated string.
    pub(super) fn as_list(&self) -> Vec<String> {
        match self {
            Node::Seq(items) => items
                .iter()
                .filter_map(Node::as_str)
                .map(str::to_owned)
                .collect(),
            _ => match self.as_str() {
                Some(text) => {
                    let inner = text
                        .strip_prefix('[')
                        .and_then(|t| t.strip_suffix(']'))
                        .unwrap_or(text);
                    inner
                        .split(',')
                        .map(|s| s.trim().trim_matches(|c| c == '"' || c == '\''))
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect()
                }
                None => Vec::new(),
            },
        }
    }

    /// The pairs of a mapping.
    pub(super) fn as_map(&self) -> Option<&[(String, Node)]> {
        match self {
            Node::Map(pairs) => Some(pairs),
            _ => None,
        }
    }

    /// Value of `key` in a mapping (first occurrence).
    pub(super) fn get(&self, key: &str) -> Option<&Node> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }
}

fn is_null_text(text: &str) -> bool {
    matches!(text.trim(), "" | "~" | "null" | "Null" | "NULL")
}
