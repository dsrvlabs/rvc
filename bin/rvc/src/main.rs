use clap::{Parser, Subcommand};
use rvc::duty_tracker::DutyTrackerService;
use rvc::metrics::server::serve_metrics;
use rvc::DutyTrackerServer;
use tonic::transport::Server;

const DEFAULT_GRPC_PORT: u16 = 8081;
const DEFAULT_METRICS_PORT: u16 = 9090;

#[derive(Parser)]
#[command(name = "rvc")]
#[command(about = "Rust Validator Client", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the validator client
    Start {
        #[arg(long, default_value_t = DEFAULT_GRPC_PORT)]
        grpc_port: u16,

        #[arg(long, default_value_t = DEFAULT_METRICS_PORT)]
        metrics_port: u16,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt::init();

    match cli.command {
        Commands::Start { grpc_port, metrics_port } => {
            start_server(grpc_port, metrics_port).await?;
        }
    }

    Ok(())
}

async fn start_server(grpc_port: u16, metrics_port: u16) -> anyhow::Result<()> {
    tracing::info!("rvc starting...");

    let addr = format!("0.0.0.0:{}", grpc_port).parse()?;
    let duty_tracker = DutyTrackerService::new();

    tracing::info!("gRPC server listening on {}", addr);

    let grpc_server =
        Server::builder().add_service(DutyTrackerServer::new(duty_tracker)).serve(addr);

    let metrics_server = async {
        if let Err(e) = serve_metrics(metrics_port).await {
            tracing::error!("Metrics server error: {}", e);
        }
    };

    tokio::select! {
        result = grpc_server => {
            if let Err(e) = result {
                tracing::error!("gRPC server error: {}", e);
            }
        }
        () = metrics_server => {
            tracing::warn!("Metrics server stopped unexpectedly");
        }
    }

    Ok(())
}
