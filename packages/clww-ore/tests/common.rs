use postgres::{Client, NoTls};
use std::fmt::{self, Display, Formatter};

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
