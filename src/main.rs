//! bm-guard — Pre-execution command guardian for interactive shell.
//!
//! Integrates guardrail's RegexEngine into a zsh accept-line hook.
//! Safe commands pass through in ~50ns (prefilter). Dangerous commands
//! are checked against 2,468+ rules via single-pass RegexSet DFA (~1-5µs).
//!
//! # Trait architecture
//!
//! `CommandValidator` abstracts the validation decision, enabling:
//! - Production: `GuardrailValidator` wrapping `RegexEngine<ProductionNormalizer>`
//! - Testing: `MockValidator` for deterministic test scenarios
//! - Custom: any impl of `CommandValidator` for domain-specific rules

use std::process;

use clap::{Parser, Subcommand};

/// Result of validating a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Command is safe to execute.
    Allow,
    /// Command is risky — show warning, require confirmation.
    Warn { rule: String, message: String },
    /// Command is dangerous — prevent execution.
    Block { rule: String, message: String },
}

/// Trait for command validation — abstracts the guardrail engine for testability.
pub trait CommandValidator: Send + Sync {
    fn validate(&self, command: &str) -> ValidationResult;
}

/// Production validator wrapping guardrail's `RegexEngine`.
pub struct GuardrailValidator {
    engine: Box<dyn guardrail::engine::RuleEngine + Send + Sync>,
}

impl GuardrailValidator {
    /// Build from default rules + rules.d directory.
    pub fn from_defaults() -> anyhow::Result<Self> {
        use guardrail::config::{DefaultsProvider, DirectoryProvider, RuleProvider};

        let mut rules = DefaultsProvider.rules()?;
        let rules_dir = guardrail::config::rules_dir();
        if rules_dir.is_dir() {
            rules.extend(DirectoryProvider { dir: rules_dir }.rules()?);
        }
        let engine = guardrail::engine::RegexEngine::new(rules)?;
        Ok(Self {
            engine: Box::new(engine),
        })
    }
}

impl CommandValidator for GuardrailValidator {
    fn validate(&self, command: &str) -> ValidationResult {
        match self.engine.check(command) {
            guardrail::model::Decision::Allow => ValidationResult::Allow,
            guardrail::model::Decision::Warn { rule, message } => {
                ValidationResult::Warn { rule, message }
            }
            guardrail::model::Decision::Block { rule, message } => {
                ValidationResult::Block { rule, message }
            }
        }
    }
}

/// Mock validator for testing — returns a fixed decision for any input.
#[cfg(test)]
pub struct MockValidator {
    pub result: ValidationResult,
}

#[cfg(test)]
impl CommandValidator for MockValidator {
    fn validate(&self, _command: &str) -> ValidationResult {
        self.result.clone()
    }
}

/// Output decision and exit with appropriate code.
fn output_decision(result: &ValidationResult) -> ! {
    match result {
        ValidationResult::Allow => process::exit(0),
        ValidationResult::Warn { rule, message } => {
            eprintln!("\x1b[33m\u{26a0} Guard warning [{rule}]: {message}\x1b[0m");
            process::exit(1);
        }
        ValidationResult::Block { rule, message } => {
            eprintln!("\x1b[31m\u{2716} Guard blocked [{rule}]: {message}\x1b[0m");
            process::exit(2);
        }
    }
}

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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let validator = GuardrailValidator::from_defaults()?;

    match cli.command {
        Commands::Check { command } => {
            output_decision(&validator.validate(&command));
        }
        Commands::Stdin => {
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let command = input.trim();
            if command.is_empty() {
                process::exit(0);
            }
            output_decision(&validator.validate(command));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mock-based tests (fast, deterministic) ──────────────────────

    #[test]
    fn mock_allow_returns_allow() {
        let v = MockValidator {
            result: ValidationResult::Allow,
        };
        assert_eq!(v.validate("anything"), ValidationResult::Allow);
    }

    #[test]
    fn mock_block_returns_block() {
        let v = MockValidator {
            result: ValidationResult::Block {
                rule: "test".into(),
                message: "blocked".into(),
            },
        };
        assert!(matches!(v.validate("anything"), ValidationResult::Block { .. }));
    }

    #[test]
    fn mock_warn_returns_warn() {
        let v = MockValidator {
            result: ValidationResult::Warn {
                rule: "test".into(),
                message: "careful".into(),
            },
        };
        assert!(matches!(v.validate("anything"), ValidationResult::Warn { .. }));
    }

    // ── Integration tests (real guardrail engine) ───────────────────

    fn production_validator() -> GuardrailValidator {
        GuardrailValidator::from_defaults().unwrap()
    }

    #[test]
    fn safe_command_allows() {
        let v = production_validator();
        assert_eq!(v.validate("git status"), ValidationResult::Allow);
    }

    #[test]
    fn ls_allows() {
        let v = production_validator();
        assert_eq!(v.validate("ls -la"), ValidationResult::Allow);
    }

    #[test]
    fn dangerous_rm_blocks() {
        let v = production_validator();
        assert!(matches!(v.validate("rm -rf /"), ValidationResult::Block { .. }));
    }

    #[test]
    fn git_force_push_detected() {
        let v = production_validator();
        assert!(!matches!(
            v.validate("git push --force origin main"),
            ValidationResult::Allow
        ));
    }

    #[test]
    fn normal_git_push_allows() {
        let v = production_validator();
        assert_eq!(v.validate("git push origin feature"), ValidationResult::Allow);
    }

    #[test]
    fn drop_table_detected() {
        let v = production_validator();
        assert!(!matches!(v.validate("DROP TABLE users"), ValidationResult::Allow));
    }

    // ── Trait object tests (verify dyn dispatch works) ──────────────

    #[test]
    fn trait_object_allow() {
        let v: Box<dyn CommandValidator> = Box::new(MockValidator {
            result: ValidationResult::Allow,
        });
        assert_eq!(v.validate("test"), ValidationResult::Allow);
    }

    #[test]
    fn trait_object_production() {
        let v: Box<dyn CommandValidator> = Box::new(production_validator());
        assert_eq!(v.validate("echo hello"), ValidationResult::Allow);
    }
}
