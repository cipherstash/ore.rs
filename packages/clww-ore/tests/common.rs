use clww_ore::ClwwOre;
use postgres::{Client, NoTls};
use std::fmt::{self, Display, Formatter};
use std::sync::OnceLock;
use vitaminc_ore::OrderKeyInit;
use vitaminc_protected::Protected;

/// The one ORE scheme the e2e tests encrypt under, made once.
pub fn scheme() -> &'static ClwwOre {
    static SCHEME: OnceLock<ClwwOre> = OnceLock::new();
    SCHEME.get_or_init(|| ClwwOre::new(Protected::new([0; 32])))
}

pub fn setup_db() -> Client {
    Client::connect("dbname=cllwtest host=localhost user=postgres", NoTls)
        .expect("Failed to connect to database")
}

#[allow(dead_code)]
pub enum SqlOp {
    Eq,
    Lt,
    Lte,
    Gt,
    Gte,
    Ne,
}

impl Display for SqlOp {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            SqlOp::Eq => write!(f, "="),
            SqlOp::Lt => write!(f, "<"),
            SqlOp::Lte => write!(f, "<="),
            SqlOp::Gt => write!(f, ">"),
            SqlOp::Gte => write!(f, ">="),
            SqlOp::Ne => write!(f, "<>"),
        }
    }
}
