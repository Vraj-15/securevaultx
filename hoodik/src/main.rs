use dotenvy::dotenv;
use error::AppResult;
use securevaultx::{Config, Context};
use migration::{Migrator, MigratorTrait};

#[actix_web::main]
async fn main() -> AppResult<()> {
    // ✅ Load environment variables from .env
    dotenvy::dotenv().ok();

    // Catch any panic from any thread running and dump it here
    // This enables us to kill the entire process if any of the child threads die
    let origin_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        origin_hook(panic_info);
        std::process::exit(1);
    }));

    // Initialize the configuration of the app
    let mut config = Config::new(
        "securevaultx",
        env!("CARGO_PKG_VERSION"),
        "securevaultx is a simple, fast and end to end encrypted cloud storage.",
    );

    config.app.ensure_data_dir(None);

    config.announce();

    // Create context from the config
    let context = Context::new(config).await?;

    // Run database migrations
    Migrator::up(&context.db, None).await?;

    // Init logger
    env_logger::init();

    // Start the server
    securevaultx::server::engage(context).await
}
