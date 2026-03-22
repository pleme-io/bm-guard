//! bm-guard — Pre-execution command guardian for interactive shell.
//!
//! Integrates guardrail's RegexEngine into a zsh preexec hook.
//! Safe commands pass through in ~50ns (prefilter). Dangerous commands
//! are checked against 2,468+ rules via single-pass RegexSet DFA (~1-5µs).
//!
//! Usage:
//!   bm-guard check "rm -rf /"          # exit 2 (block)
//!   bm-guard check "git status"        # exit 0 (allow)
//!   echo "rm -rf /" | bm-guard stdin   # read from stdin

use std::process;

use clap::{Parser, Subcommand};
use guardrail::config::{DefaultsProvider, DirectoryProvider, RuleProvider};
use guardrail::engine::{RegexEngine, RuleEngine};
use guardrail::model::Decision;

#[derive(Parser)]
#[command(name = "bm-guard", about = "Pre-execution command guardian")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check a command for safety (exit 0=allow, 1=warn, 2=block)
    Check {
        /// The command to validate
        command: String,
    },
    /// Read command from stdin (for piped usage)
    Stdin,
}

/// Build the production rule engine with defaults + rules.d directory.
fn build_engine() -> anyhow::Result<impl RuleEngine> {
    let mut rules = DefaultsProvider.rules()?;

    let rules_dir = guardrail::config::rules_dir();
    if rules_dir.is_dir() {
        rules.extend(DirectoryProvider { dir: rules_dir }.rules()?);
    }

    RegexEngine::new(rules)
}

/// Output decision as JSON and exit with appropriate code.
fn output_decision(decision: &Decision) -> ! {
    match decision {
        Decision::Allow => {
            process::exit(0);
        }
        Decision::Warn { rule, message } => {
            eprintln!("\x1b[33m⚠ Guard warning [{rule}]: {message}\x1b[0m");
            process::exit(1);
        }
        Decision::Block { rule, message } => {
            eprintln!("\x1b[31m✖ Guard blocked [{rule}]: {message}\x1b[0m");
            process::exit(2);
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let engine = build_engine()?;

    match cli.command {
        Commands::Check { command } => {
            output_decision(&engine.check(&command));
        }
        Commands::Stdin => {
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let command = input.trim();
            if command.is_empty() {
                process::exit(0);
            }
            output_decision(&engine.check(command));
        }
    }
}

#[cfg(test)]
mod tests {
    use guardrail::config::{DefaultsProvider, RuleProvider};
    use guardrail::engine::{IdentityNormalizer, NullPrefilter, RegexEngine, RuleEngine};
    use guardrail::model::Decision;

    fn test_engine() -> RegexEngine<IdentityNormalizer, NullPrefilter> {
        let rules = DefaultsProvider.rules().unwrap();
        RegexEngine::with_plugins(rules, IdentityNormalizer, NullPrefilter).unwrap()
    }

    #[test]
    fn safe_command_allows() {
        let engine = test_engine();
        assert!(matches!(engine.check("git status"), Decision::Allow));
    }

    #[test]
    fn dangerous_rm_blocks() {
        let engine = test_engine();
        assert!(matches!(engine.check("rm -rf /"), Decision::Block { .. }));
    }

    #[test]
    fn git_force_push_detected() {
        let engine = test_engine();
        let decision = engine.check("git push --force origin main");
        assert!(!matches!(decision, Decision::Allow));
    }

    #[test]
    fn normal_git_push_allows() {
        let engine = test_engine();
        assert!(matches!(engine.check("git push origin feature"), Decision::Allow));
    }

    #[test]
    fn normal_ls_allows() {
        let engine = test_engine();
        assert!(matches!(engine.check("ls -la"), Decision::Allow));
    }

    #[test]
    fn drop_table_detected() {
        let engine = test_engine();
        let decision = engine.check("DROP TABLE users");
        assert!(!matches!(decision, Decision::Allow));
    }
}
