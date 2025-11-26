#![warn(clippy::unwrap_used)]

pub mod resources;
pub mod errors;
pub mod utilities;
mod routes;

use local_ip_address::local_ip;
use tokio::net::TcpListener;
use colored::Colorize;

const DEFAULT_APP_PORT: i16 = 8080;

fn print_shutdown_message() {

  println!("{}", "Slashstep Server is shutting down...".blue());

}

async fn gracefully_shutdown() {

  let ctrl_c = async {
    tokio::signal::ctrl_c()
      .await
      .expect("failed to install Ctrl+C handler");
  };

  #[cfg(unix)]
  let terminate = async {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
      .expect("failed to install signal handler")
      .recv()
      .await;
  };

  #[cfg(not(unix))]
  let terminate = std::future::pending::<()>();

  tokio::select! {
    _ = ctrl_c => {
      
      print_shutdown_message();

    },
    _ = terminate => {

      print_shutdown_message();

    },
  }

}

fn get_app_port_string() -> String {

  match std::env::var("APP_PORT") {
    Ok(app_port) => app_port,
    Err(_) => {
      println!("{}", format!("Please set an APP_PORT environment variable. Defaulting to {}.", DEFAULT_APP_PORT).yellow());
      DEFAULT_APP_PORT.to_string()
    }
  }

}

#[derive(Debug)]
enum AppError {
  STDIOError(std::io::Error),
  LocalIPAddressError(local_ip_address::Error)
}

impl From<std::io::Error> for AppError {
  fn from(error: std::io::Error) -> Self {
    AppError::STDIOError(error)
  }
}

impl From<local_ip_address::Error> for AppError {
  fn from(error: local_ip_address::Error) -> Self {
    AppError::LocalIPAddressError(error)
  }
}

#[tokio::main]
async fn main() -> Result<(), AppError> {

  println!("Slashstep Server v{}", env!("CARGO_PKG_VERSION"));

  if dotenvy::dotenv().is_ok() {

    println!("{}", "Successfully imported environment variables from .env file.".blue());

  }

  let app_port = get_app_port_string();
  let router = routes::get_router();
  let listener = TcpListener::bind(format!("0.0.0.0:{}", app_port)).await?;
  let app_ip = local_ip()?;
  println!("{}", format!("Slashstep Server is now listening on port {}. You can access it on your machine at http://localhost:{}, or your local network at http://{}:{}.", app_port, app_port, app_ip, app_port).green());
  axum::serve(listener, router)
    .with_graceful_shutdown(gracefully_shutdown())
    .await?;

  return Ok(());

}