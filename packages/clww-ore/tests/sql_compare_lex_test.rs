mod common;
use clww_ore::OreClww8VariableV1;
use common::*;
use quickcheck::{quickcheck, TestResult};
use vitaminc_ore::target::Text;
use vitaminc_ore::OrderEncrypt;

/// The ORE term of `s` in a `Text` space, or `None` for text vitaminc
/// refuses (an unassigned code point, say).
fn try_term(s: &str) -> Option<OreClww8VariableV1> {
    let space = scheme().target(Text).context("sql-compare-lex");
    space.encrypt_checked(s).ok().map(|t| t.into_raw())
}

fn term(s: &str) -> OreClww8VariableV1 {
    try_term(s).unwrap()
}

fn sql_compare_lex(a: &OreClww8VariableV1, b: &OreClww8VariableV1) -> i32 {
    let response = setup_db()
        .query("SELECT compare_lex_ore_cllw_8_v1($1, $2)", &[&a, &b])
        .expect("Failed to execute query");

    let row = response.first().expect("Expected a result");

    row.get(0)
}

/// Compare two values using a SQL operator.
fn sql_compare_lex_op(a: &OreClww8VariableV1, b: &OreClww8VariableV1, op: SqlOp) -> bool {
    let query = format!("SELECT $1::ore_cllw_8_variable_v1 {op} $2::ore_cllw_8_variable_v1");

    let response = setup_db()
        .query(&query, &[&a, &b])
        .expect("Failed to execute query");

    let row = response.first().expect("Expected a result");

    row.get(0)
}

#[test]
#[ignore = "E2E"]
fn test_compare_string_eq() {
    let (a, b) = (term("cat"), term("cat"));

    assert_eq!(sql_compare_lex(&a, &b), 0);
}

#[test]
#[ignore = "E2E"]
fn test_compare_string_prefix() {
    let (a, b) = (term("cat"), term("catskills"));

    assert_eq!(sql_compare_lex(&a, &b), -1);
}

#[test]
#[ignore = "E2E"]
fn test_compare_string_prefix_lt() {
    let (a, b) = (term("cat"), term("catskills"));

    assert!(sql_compare_lex_op(&a, &b, SqlOp::Lt));
    assert!(sql_compare_lex_op(&a, &b, SqlOp::Lte));
    assert!(sql_compare_lex_op(&a, &b, SqlOp::Ne));

    // Refutes
    assert!(!sql_compare_lex_op(&a, &b, SqlOp::Gte));
    assert!(!sql_compare_lex_op(&a, &b, SqlOp::Gt));
    assert!(!sql_compare_lex_op(&a, &b, SqlOp::Eq));
}

quickcheck! {
    #[ignore = "e2e"]
    fn prop_compare_string_eq(x: String) -> TestResult {
        let Some(a) = try_term(&x) else {
            return TestResult::discard();
        };
        let b = term(&x);

        TestResult::from_bool(sql_compare_lex_op(&a, &b, SqlOp::Eq))
    }
}
