use clap::Parser;

#[derive(Parser)]
#[command(
    name = clap::crate_name!(),
    version = clap::crate_version!(),
    author = clap::crate_authors!(),
    about = clap::crate_description!()
)]
pub(crate) struct Args {
    #[arg(short, long)]
    pub config: String,
}