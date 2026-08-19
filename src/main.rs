use clap::{Args, Parser, Subcommand};
use simvader::install::{self, InstallOptions};
use simvader::{audit, config, gateway, http, policy, reflect};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Parser)]
#[command(name = "simvader", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Front multiple downstream MCP servers from a config file (the security layer).
    Gateway {
        /// Path to the Simvader config listing downstream servers.
        #[arg(long, default_value = "simvader.json")]
        config: PathBuf,
        #[command(flatten)]
        flags: CommonFlags,
    },
    /// Wrap a single MCP server (the N=1 case): simvader run [flags] -- <command> [args…]
    Run {
        #[command(flatten)]
        flags: CommonFlags,
        /// The downstream MCP server command and its arguments (after `--`).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        target: Vec<String>,
    },
    /// Migrate an MCP client's configured servers behind the gateway (Claude Desktop by default).
    Install {
        #[arg(long, default_value = "simvader.json")]
        config: PathBuf,
        /// Target a specific client config file instead of scanning default locations.
        #[arg(long)]
        client_config: Option<PathBuf>,
        /// Show the planned changes without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Revert `install`, restoring each client config from its Simvader backup.
    Uninstall {
        #[arg(long, default_value = "simvader.json")]
        config: PathBuf,
        #[arg(long)]
        client_config: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Args)]
struct CommonFlags {
    /// Log detections but forward the call instead of blocking it.
    #[arg(long)]
    audit: bool,
    /// Do not augment tool descriptions with security guidance.
    #[arg(long)]
    no_augment: bool,
    /// Escalate ambiguous (Suspicious) calls to an LLM reflector (needs ANTHROPIC_API_KEY;
    /// requires building with `--features llm`).
    #[arg(long)]
    reflect_llm: bool,
    /// Load a per-tool allow/deny policy (JSON). An allowlist is default-deny.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Default-deny: refuse any call the policy does not explicitly allow (use with --policy).
    #[arg(long)]
    default_deny: bool,
    /// Fail closed: deny ambiguous (Suspicious) calls instead of allowing them, when no LLM
    /// reflector is configured.
    #[arg(long)]
    fail_closed: bool,
    /// Resolve hostnames through DNS during SSRF checks to catch domains that point at internal
    /// addresses. Adds a blocking lookup off the fast path.
    #[arg(long)]
    resolve: bool,
    /// Append a structured JSONL audit event per tool call to this file.
    #[arg(long)]
    audit_log: Option<PathBuf>,
    /// Observe traffic and write a proposed allowlist to simvader-policy.proposed.json on exit.
    /// Implies --audit (never blocks).
    #[arg(long)]
    learn: bool,
    /// Serve over HTTP on this address (e.g. 127.0.0.1:8080) instead of stdio. Lets MCP clients
    /// connect to Simvader as a service.
    #[arg(long, value_name = "ADDR")]
    http: Option<String>,
    /// Verbose per-call logging to stderr.
    #[arg(short, long)]
    verbose: bool,
}

impl CommonFlags {
    fn to_options(&self) -> gateway::Options {
        gateway::Options {
            audit: self.audit,
            augment: !self.no_augment,
            verbose: self.verbose,
            // TODO(reflect-cli): no `--reflect ask/askstrict` flag is wired yet; default to the
            // neutral Off mode (escalation still honours `--reflect-llm` via the reflector).
            reflect: gateway::ReflectMode::Off,
            default_deny: self.default_deny,
            resolve: self.resolve,
        }
    }
}

/// Assemble the full gateway runtime config from CLI flags (policy, audit sink, learner, reflector).
fn build_gateway_config(flags: &CommonFlags) -> std::io::Result<gateway::GatewayConfig> {
    let mut options = flags.to_options();

    let policy = match &flags.policy {
        Some(path) => policy::Policy::load(path)?,
        None => policy::Policy::default(),
    };
    let audit = match &flags.audit_log {
        Some(path) => Some(audit::AuditSink::to_file(path)?),
        None => None,
    };
    let (learner, learn_out) = if flags.learn {
        options.audit = true; // learn mode observes only, never blocks
        (Some(Mutex::new(policy::Learner::default())), Some(PathBuf::from("simvader-policy.proposed.json")))
    } else {
        (None, None)
    };

    Ok(gateway::GatewayConfig {
        options,
        reflector: build_reflector(flags.reflect_llm, flags.fail_closed),
        policy,
        audit,
        learner,
        learn_out,
    })
}

/// Build the escalation reflector. `--reflect-llm` selects the LLM reflector when the binary was
/// built with the `llm` feature and a key is present. Otherwise `--fail-closed` denies ambiguous
/// calls, and the default is the fail-open `NoopReflector`.
fn build_reflector(reflect_llm: bool, fail_closed: bool) -> Box<dyn reflect::Reflector> {
    if reflect_llm {
        #[cfg(feature = "llm")]
        {
            match reflect::LlmReflector::from_env() {
                Some(r) => {
                    eprintln!("[simvader] LLM reflection enabled (Suspicious calls escalate to Claude)");
                    return Box::new(r);
                }
                None => eprintln!(
                    "[simvader] --reflect-llm set but ANTHROPIC_API_KEY is missing; using deterministic guard only"
                ),
            }
        }
        #[cfg(not(feature = "llm"))]
        eprintln!(
            "[simvader] --reflect-llm set but this binary was built without the 'llm' feature; using deterministic guard only"
        );
    }
    if fail_closed {
        eprintln!("[simvader] fail-closed: ambiguous (Suspicious) calls will be denied");
        return Box::new(reflect::DenyReflector);
    }
    Box::new(reflect::NoopReflector)
}

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Gateway { config, flags } => {
            let cfg = config::Config::load(&config)?;
            let gwcfg = build_gateway_config(&flags)?;
            match &flags.http {
                Some(addr) => http::serve_http(cfg.servers, gwcfg, addr),
                None => gateway::run(cfg.servers, gwcfg),
            }
        }
        Command::Run { flags, target } => {
            let (command, args) = target.split_first().expect("clap requires a non-empty target");
            let server = config::DownstreamServer {
                alias: config::alias_from_command(command),
                command: command.clone(),
                args: args.to_vec(),
                env: Default::default(),
            };
            let gwcfg = build_gateway_config(&flags)?;
            match &flags.http {
                Some(addr) => http::serve_http(vec![server], gwcfg, addr),
                None => gateway::run(vec![server], gwcfg),
            }
        }
        Command::Install { config, client_config, dry_run } => {
            install::install(InstallOptions { simvader_config: config, client_config, dry_run })
        }
        Command::Uninstall { config, client_config, dry_run } => {
            install::uninstall(InstallOptions { simvader_config: config, client_config, dry_run })
        }
    }
}
