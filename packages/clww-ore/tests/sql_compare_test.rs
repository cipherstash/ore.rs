mod common;
use clww_ore::OreClww8VariableV1;
use common::*;
use quickcheck::quickcheck;
use std::cmp::Ordering;
use vitaminc_ore::target::U64;
use vitaminc_ore::OrderEncrypt;

/// The ORE term of `x` in a `U64` space. Every term is variable-length now,
/// and a `u64`'s is 64 bytes, as the fixed `ore_cllw_8_v1` type held them.
fn term(x: u64) -> OreClww8VariableV1 {
    let space = scheme().target(U64).context("sql-compare");
    space.encrypt(x).unwrap().into_raw()
}

/// Compare two terms as `ore_cllw_8_v1` values, with the SQL function.
fn sql_compare(a: &OreClww8VariableV1, b: &OreClww8VariableV1) -> i32 {
    let response = setup_db()
        .query(
            "SELECT compare_ore_cllw_8_v1(ROW($1::bytea)::ore_cllw_8_v1, ROW($2::bytea)::ore_cllw_8_v1)",
            &[&a.as_ref(), &b.as_ref()],
        )
        .expect("Failed to execute query");

    let row = response.first().expect("Expected a result");

    row.get(0)
}

/// Compare two terms as `ore_cllw_8_v1` values, with a SQL operator.
fn sql_compare_op(a: &OreClww8VariableV1, b: &OreClww8VariableV1, op: SqlOp) -> bool {
    let query = format!("SELECT ROW($1::bytea)::ore_cllw_8_v1 {op} ROW($2::bytea)::ore_cllw_8_v1");

    let response = setup_db()
        .query(&query, &[&a.as_ref(), &b.as_ref()])
        .expect("Failed to execute query");

    let row = response.first().expect("Expected a result");

    row.get(0)
}

fn expect(a: u64, b: u64) -> i32 {
    match a.cmp(&b) {
        Ordering::Less => -1,
        Ordering::Greater => 1,
        Ordering::Equal => 0,
    }
}

quickcheck! {
    #[ignore = "e2e"]
    fn test_compare_u64_eq(x: u64) -> bool {
        let (a, b) = (term(x), term(x));

        sql_compare(&a, &b) == 0
    }

    #[ignore = "e2e"]
    fn test_compare_u64_eq_op(x: u64) -> bool {
        let (a, b) = (term(x), term(x));

        sql_compare_op(&a, &b, SqlOp::Eq)
    }

    #[ignore = "e2e"]
    fn test_compare_u64_cmp(a: u64, b: u64) -> bool {
        let (x, y) = (term(a), term(b));

        expect(a, b) == sql_compare(&x, &y)
    }

    #[ignore = "e2e"]
    fn test_compare_u64_cmp_op(a: u64, b: u64) -> bool {
        let (x, y) = (term(a), term(b));

        match a.cmp(&b) {
            Ordering::Less => {
                sql_compare_op(&x, &y, SqlOp::Lt)
                    && sql_compare_op(&x, &y, SqlOp::Lte)
                    && sql_compare_op(&x, &y, SqlOp::Ne)
            }
            Ordering::Greater => {
                sql_compare_op(&x, &y, SqlOp::Gt)
                    && sql_compare_op(&x, &y, SqlOp::Gte)
                    && sql_compare_op(&x, &y, SqlOp::Ne)
            }
            Ordering::Equal => {
                sql_compare_op(&x, &y, SqlOp::Eq)
                    && sql_compare_op(&x, &y, SqlOp::Gte)
                    && sql_compare_op(&x, &y, SqlOp::Lte)
            }
        }
    }
}
