mod common;
use clww_ore::{Key, OreClww8V1};
use common::*;
use quickcheck::quickcheck;
use std::cmp::Ordering;

/// Compare two values using a SQL function.
fn sql_compare<const N: usize>(a: &OreClww8V1<N>, b: &OreClww8V1<N>) -> i32 {
    let response = setup_db()
        .query("SELECT compare_ore_cllw_8_v1($1, $2)", &[&a, &b])
        .expect("Failed to execute query");

    let row = response.first().expect("Expected a result");

    row.get(0)
}

/// Compare two values using a SQL operator.
fn sql_compare_op<const N: usize>(a: &OreClww8V1<N>, b: &OreClww8V1<N>, op: SqlOp) -> bool {
    let query = format!("SELECT $1::ore_cllw_8_v1 {op} $2::ore_cllw_8_v1");

    let response = setup_db()
        .query(&query, &[&a, &b])
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
        let key = Key::from([0; 32]);
        let a = key.encrypt::<u64>(x).unwrap();
        let b = key.encrypt::<u64>(x).unwrap();

        sql_compare(&a, &b) == 0
    }

    #[ignore = "e2e"]
    fn test_compare_u64_eq_op(x: u64) -> bool {
        let key = Key::from([0; 32]);
        let a = key.encrypt::<u64>(x).unwrap();
        let b = key.encrypt::<u64>(x).unwrap();

        sql_compare_op(&a, &b, SqlOp::Eq)
    }

    #[ignore = "e2e"]
    fn test_compare_u64_cmp(a: u64, b: u64) -> bool {
        let key = Key::from([0; 32]);
        let x = key.encrypt::<u64>(a).unwrap();
        let y = key.encrypt::<u64>(b).unwrap();

        expect(a, b) == sql_compare(&x, &y)
    }

    #[ignore = "e2e"]
    fn test_compare_u64_cmp_op(a: u64, b: u64) -> bool {
        let key = Key::from([0; 32]);
        let x = key.encrypt::<u64>(a).unwrap();
        let y = key.encrypt::<u64>(b).unwrap();

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
