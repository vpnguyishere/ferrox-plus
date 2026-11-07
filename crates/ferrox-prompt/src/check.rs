//! The gate `ci.yml` runs on the library's shape — touches, gates, placeholders, graph, restated prose — never a judgement of prose quality.

use std::collections::BTreeMap;
use std::path::Path;

use crate::markdown::{Addon, Diagnostic, Library, Prompt, Touch};

/// A run of this many content words that the shared protocol already carries is a restatement, not a coincidence.
const RESTATEMENT_RUN: usize = 5;
/// The same, between two templates, where a shared turn of phrase can be deliberate.
const ECHO_RUN: usize = 6;

/// The words that carry a sentence's meaning, in order: a function word, a number, a code span or a `{blank}` is no evidence of copying, so it drops out.
fn content_tokens(text: &str) -> Vec<String> {
    const STOP: &[&str] = &[
        "a", "an", "and", "are", "as", "at", "be", "been", "but", "by", "can", "could", "did",
        "do", "does", "for", "from", "had", "has", "have", "he", "her", "his", "if", "in", "is",
        "it", "its", "may", "might", "must", "no", "nor", "not", "of", "on", "or", "our", "she",
        "so", "than", "that", "the", "their", "them", "then", "there", "these", "they", "this",
        "to", "too", "us", "was", "we", "were", "what", "when", "which", "who", "will", "would",
        "you", "your",
    ];
    let mut stripped = String::new();
    let mut in_code = false;
    let mut in_blank = false;
    for character in text.chars() {
        match character {
            '`' => in_code = !in_code,
            '{' => in_blank = true,
            '}' => in_blank = false,
            _ => {
                if !in_code && !in_blank {
                    stripped.push(character);
                }
            }
        }
    }
    stripped
        .split(|character: char| !character.is_alphanumeric())
        .map(str::to_lowercase)
        .filter(|word| {
            word.len() > 2 && !word.chars().all(char::is_numeric) && !STOP.contains(&word.as_str())
        })
        .collect()
}

/// The longest run of consecutive words `a` and `b` share, and the phrase.
fn longest_shared_run(a: &[String], b: &[String]) -> (usize, String) {
    let mut at: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (index, word) in a.iter().enumerate() {
        at.entry(word.as_str()).or_default().push(index);
    }
    let mut best = 0;
    let mut phrase = String::new();
    for (start_b, word) in b.iter().enumerate() {
        let Some(starts) = at.get(word.as_str()) else {
            continue;
        };
        for &start_a in starts {
            let mut run = 0;
            while start_a + run < a.len()
                && start_b + run < b.len()
                && a[start_a + run] == b[start_b + run]
            {
                run += 1;
            }
            if run > best {
                best = run;
                phrase = a[start_a..start_a + run].join(" ");
            }
        }
    }
    (best, phrase)
}

/// The texts a handout actually carries: the protocol line, the body, and every add-on — not the lines only `list` reads.
fn handout_texts(prompt: &Prompt) -> Vec<(String, Vec<String>)> {
    let mut texts: Vec<(String, Vec<String>)> = Vec::new();
    if !prompt.protocol.is_empty() {
        texts.push((
            "**Prompt protocol:**".to_owned(),
            content_tokens(&prompt.protocol),
        ));
    }
    texts.push(("body".to_owned(), content_tokens(&prompt.body)));
    for addon in &prompt.addons {
        let Addon { body, slug, .. } = addon;
        texts.push((format!("add-on `{slug}`"), content_tokens(body)));
    }
    texts
}

/// Prose the shared protocol already says, and prose two templates both say.
fn check_restatements(library: &Library, findings: &mut Vec<Diagnostic>) {
    let protocol = content_tokens(&library.shared_protocol);
    let mut carried: Vec<(u32, usize, String, Vec<String>)> = Vec::new();
    for prompt in &library.prompts {
        for (label, tokens) in handout_texts(prompt) {
            if !protocol.is_empty() {
                let (run, phrase) = longest_shared_run(&protocol, &tokens);
                if run >= RESTATEMENT_RUN {
                    findings.push(Diagnostic::error(
                        prompt.line,
                        format!(
                            "P{}: its {label} repeats the shared protocol for {run} words \
                             (\"{phrase}\"); every handout already carries that rule, so keep only \
                             what this slice adds",
                            prompt.id
                        ),
                    ));
                }
            }
            carried.push((prompt.id, prompt.line, label, tokens));
        }
    }
    for first in 0..carried.len() {
        for second in first + 1..carried.len() {
            let (one, _, _, a) = &carried[first];
            let (two, line, label_two, b) = &carried[second];
            if one == two {
                continue;
            }
            let (run, phrase) = longest_shared_run(a, b);
            if run >= ECHO_RUN {
                findings.push(Diagnostic::warning(
                    *line,
                    format!(
                        "P{two}: its {label_two} echoes P{one} for {run} words (\"{phrase}\"); one \
                         of the two should say it, or the phrase is load-bearing and belongs in the \
                         shared protocol",
                    ),
                ));
            }
        }
    }
}

/// Parser findings plus filesystem and roadmap-wide ones; `verify_paths` is false for an outside library, and the report says what was skipped.
pub fn run(library: &Library, root: &Path, verify_paths: bool) -> Vec<Diagnostic> {
    let mut findings = library.diagnostics.clone();
    if !verify_paths {
        findings.push(Diagnostic::warning(
            0,
            format!(
                "this library is outside {}, so **Touches:** and the workflows its gates name \
                 were not checked",
                root.display()
            ),
        ));
    }
    for prompt in &library.prompts {
        if verify_paths {
            check_touches(prompt, root, &mut findings);
        }
        check_gates(prompt, root, verify_paths, &mut findings);
        check_placeholders(prompt, &mut findings);
    }
    check_roadmap(library, &mut findings);
    check_restatements(library, &mut findings);
    findings.sort_by_key(|finding| (finding.line, finding.severity));
    findings
}

/// Paths this prompt claims, against what is actually there.
fn check_touches(prompt: &Prompt, root: &Path, findings: &mut Vec<Diagnostic>) {
    for touch in &prompt.touches {
        let path = touch.path();
        let full = root.join(path);
        match touch {
            Touch::Existing(_) if !full.exists() => findings.push(Diagnostic::error(
                prompt.line,
                format!(
                    "P{}: **Touches:** `{path}` does not exist, so this slice points at a file \
                     nothing will edit",
                    prompt.id
                ),
            )),
            Touch::Created(_) if full.exists() => findings.push(Diagnostic::error(
                prompt.line,
                format!(
                    "P{}: **Touches:** `+{path}` already exists, so this slice claims to create a \
                     file that is there — mark the prompt done, or file it against the real path",
                    prompt.id
                ),
            )),
            _ => {}
        }
    }
}

/// Gates against the repository they name.
fn check_gates(prompt: &Prompt, root: &Path, verify_paths: bool, findings: &mut Vec<Diagnostic>) {
    let workflows = root.join(".github/workflows");
    for gate in &prompt.gates {
        let trimmed = gate.trim();
        if looks_like_a_command(trimmed) && !trimmed.starts_with('`') {
            findings.push(Diagnostic::warning(
                prompt.line,
                format!(
                    "P{}: the gate `{trimmed}` is a command written as plain text; wrap it in \
                     backticks so it reads as one",
                    prompt.id
                ),
            ));
        }
        if !verify_paths {
            continue;
        }
        for token in trimmed.split(|character: char| character.is_whitespace() || character == ',')
        {
            // A `§`-prefixed gate is the conditional form: it names the same workflow.
            let name = token
                .trim_matches('`')
                .strip_prefix('§')
                .unwrap_or_else(|| token.trim_matches('`'));
            // Case-insensitive: `CI.yml` and `ci.yml` are one workflow to the author, two strings to a byte compare.
            let extension = Path::new(name)
                .extension()
                .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            let names_a_workflow =
                matches!(extension.as_str(), "yml" | "yaml") && !name.contains('/');
            if names_a_workflow && !workflows.join(name).is_file() {
                findings.push(Diagnostic::error(
                    prompt.line,
                    format!(
                        "P{}: the gate names `{name}`, which is not in .github/workflows/; a gate \
                         that names a job which does not exist is a promise, not a check",
                        prompt.id
                    ),
                ));
            }
        }
    }
}

/// Whether a gate opens like a shell command.
fn looks_like_a_command(gate: &str) -> bool {
    const OPENERS: &[&str] = &[
        "cargo ", "./", "bash ", "sh ", "git ", "gh ", "make ", "npm ",
    ];
    OPENERS.iter().any(|opener| gate.starts_with(opener))
}

/// Defaults that are empty, which render as a hole that looks like a value.
fn check_placeholders(prompt: &Prompt, findings: &mut Vec<Diagnostic>) {
    for placeholder in &prompt.placeholders {
        if placeholder.default.as_deref() == Some("") {
            findings.push(Diagnostic::warning(
                prompt.line,
                format!(
                    "P{}: `{{{} =}}` has an empty default; give it a value or drop the `=` so it \
                     reads as required",
                    prompt.id, placeholder.name
                ),
            ));
        }
    }
}

/// Checks about the roadmap as a whole.
fn check_roadmap(library: &Library, findings: &mut Vec<Diagnostic>) {
    let open: Vec<&Prompt> = library
        .prompts
        .iter()
        .filter(|prompt| prompt.is_open())
        .collect();
    if open.is_empty() {
        findings.push(Diagnostic::warning(
            0,
            "no prompt is `todo` or `blocked`: the roadmap has nothing to offer, so `next` will \
             only ever say so",
        ));
    }

    // Files more than one available prompt claims. See `contention`.
    for prompt in library
        .prompts
        .iter()
        .filter(|prompt| is_available(library, prompt))
    {
        for clash in contention(library, prompt) {
            findings.push(Diagnostic::warning(
                prompt.line,
                format!(
                    "P{} and {} are both open now and both claim `{}`; they are one slice, or two \
                     that must be taken in order",
                    prompt.id,
                    clash
                        .also
                        .iter()
                        .map(|id| format!("P{id}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    clash.path
                ),
            ));
        }
    }
}

/// Started or ready now: only two *available* slices claiming one file is a real ordering decision.
pub fn is_available(library: &Library, prompt: &Prompt) -> bool {
    prompt.status == crate::markdown::Status::Doing
        || crate::advisor::readiness(library, prompt) == crate::advisor::Readiness::Ready
}

/// A file this prompt shares with another available prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contention {
    /// The path, as both prompts write it.
    pub path: String,
    /// The other prompts that are available and claim it.
    pub also: Vec<u32>,
}

/// Files `prompt` shares with a prompt the advisor could also be asked for.
pub fn contention(library: &Library, prompt: &Prompt) -> Vec<Contention> {
    let mut found: Vec<Contention> = Vec::new();
    for path in prompt.existing_paths() {
        let also: Vec<u32> = library
            .prompts
            .iter()
            .filter(|other| other.id != prompt.id)
            .filter(|other| is_available(library, other))
            .filter(|other| other.existing_paths().any(|claimed| claimed == path))
            .map(|other| other.id)
            .collect();
        if !also.is_empty() {
            found.push(Contention {
                path: path.to_owned(),
                also,
            });
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::markdown::Library;

    fn load(text: &str) -> Library {
        Library::parse(Path::new("prompts.md"), text)
    }

    const GOOD: &str = "\
## Shared protocol

```text
p
```

## P1 · One

**When to use:** now
**Status:** todo
**Leverage:** 3
**Effort:** small
**Gates:** `cargo test`; CI: `ci.yml`
**Touches:** Cargo.toml

```text
body
```
";

    #[test]
    fn a_body_that_restates_the_shared_protocol_is_an_error() {
        let text = GOOD.replace(
            "p\n```",
            "p\nThe bar is the best implementation, not a working one\n```",
        );
        let library = load(&text.replace(
            "```text\nbody",
            "```text\nThe bar is the best implementation, not a working one here",
        ));
        let findings = run(&library, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("repeats the shared protocol")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_body_that_agrees_with_the_protocol_in_other_words_is_fine() {
        let library = load(&GOOD.replace(
            "```text\nbody",
            "```text\nAim past the passing build: the reference sets the floor, and this tree has to beat it",
        ));
        let findings = run(&library, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .all(|finding| !finding.message.contains("repeats the shared protocol")),
            "{findings:#?}"
        );
    }

    #[test]
    fn two_bodies_that_echo_each_other_are_a_warning() {
        let shared = "fold the record layer framing into one helper everywhere";
        let one = GOOD.replace(
            "```text\nbody",
            &format!("```text\nbody, and {shared} once"),
        );
        let text = format!(
            "{one}\n## P2 · Two\n\n**When to use:** now\n**Status:** todo\n**Leverage:** 1\n\
             **Effort:** small\n**Gates:** `cargo test`\n\n```text\n{shared} twice\n```\n"
        );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("echoes P1")),
            "{findings:#?}"
        );
    }

    #[test]
    fn the_live_library_passes_its_own_gate() {
        let library = crate::load_library(None, Path::new(env!("CARGO_MANIFEST_DIR")))
            .expect("the library is next to this crate");
        let root = crate::workspace_root(Path::new(env!("CARGO_MANIFEST_DIR")));
        let findings = run(&library, &root, true);
        let errors: Vec<&Diagnostic> = findings
            .iter()
            .filter(|finding| finding.severity == crate::markdown::Severity::Error)
            .collect();
        assert!(
            errors.is_empty(),
            "prompts.md fails its own gate: {errors:#?}"
        );
    }

    #[test]
    fn a_touch_at_a_missing_file_is_an_error() {
        let library = load(&GOOD.replace("Cargo.toml", "crates/gone.rs"));
        let findings = run(&library, Path::new("/nonexistent-root"), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("does not exist")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_touch_at_an_existing_file_is_fine_against_the_real_root() {
        let library = load(GOOD);
        let root = crate::manifest_root();
        let findings = run(&library, &root, true);
        assert!(findings
            .iter()
            .all(|finding| !finding.message.contains("does not exist")));
    }

    #[test]
    fn a_created_file_that_already_exists_is_an_error() {
        let library = load(&GOOD.replace("Cargo.toml", "+Cargo.toml"));
        let root = crate::manifest_root();
        let findings = run(&library, &root, true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("already exists")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_gate_naming_a_missing_workflow_is_an_error() {
        let library = load(&GOOD.replace("CI: `ci.yml`", "CI: `no-such.yml`"));
        let findings = run(&library, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("not in .github/workflows")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_command_gate_without_backticks_is_a_warning() {
        let library = load(&GOOD.replace("`cargo test`", "cargo test"));
        let findings = run(&library, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("wrap it in")),
            "{findings:#?}"
        );
    }

    #[test]
    fn two_open_prompts_claiming_one_file_are_reported() {
        let text = format!(
            "{GOOD}\n## P2 · Two\n\n**When to use:** now\n**Status:** todo\n**Leverage:** 1\n\
             **Effort:** small\n**Gates:** `cargo test`\n**Touches:** Cargo.toml\n\n```text\nb\n```\n"
        );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("both claim")),
            "{findings:#?}"
        );
    }

    #[test]
    fn an_empty_default_is_a_warning() {
        let library = load(&GOOD.replace("```text\nbody", "```text\nbody {a=}"));
        let findings = run(&library, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("empty default")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_finished_roadmap_says_so() {
        let text = GOOD.replace("**Status:** todo", "**Status:** done");
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("nothing to offer")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_library_outside_the_repository_says_which_checks_were_skipped() {
        let findings = run(&load(GOOD), &crate::manifest_root(), false);
        let note = findings
            .iter()
            .find(|finding| finding.message.contains("were not checked"))
            .unwrap_or_else(|| panic!("a skipped check must be said out loud: {findings:#?}"));
        assert!(note.message.contains("**Touches:**"));
    }
}
