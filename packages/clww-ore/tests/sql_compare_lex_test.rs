mod common;
use common::*; 
use cllw_ore::{Key, OreCllw8VariableV1};
use quickcheck::{quickcheck, TestResult};

fn sql_compare_lex(a: &OreCllw8VariableV1, b: &OreCllw8VariableV1) -> i32 {
    let response = setup_db()
        .query("SELECT compare_lex_ore_cllw_8_v1($1, $2)", &[&a, &b])
        .expect("Failed to execute query");

    let row = response.first().expect("Expected a result");

    row.get(0)
}

/// Compare two values using a SQL operator.
fn sql_compare_lex_op(a: &OreCllw8VariableV1, b: &OreCllw8VariableV1, op: SqlOp) -> bool {
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
    let key = Key::from([0; 32]);
    let a = key.encrypt("cat").unwrap();
    let b = key.encrypt("cat").unwrap();

    assert_eq!(sql_compare_lex(&a, &b), 0);
}

#[test]
#[ignore = "E2E"]
fn test_compare_string_prefix() {
    let key = Key::from([0; 32]);
    let a = key.encrypt("cat").unwrap();
    let b = key.encrypt("catskills").unwrap();

    assert_eq!(sql_compare_lex(&a, &b), 1);
}

#[test]
#[ignore = "E2E"]
fn test_compare_string_prefix_gt() {
    let key = Key::from([0; 32]);
    let a = key.encrypt("cat").unwrap();
    let b = key.encrypt("catskills").unwrap();

    assert!(sql_compare_lex_op(&a, &b, SqlOp::Gt));
    assert!(sql_compare_lex_op(&a, &b, SqlOp::Gte));
    assert!(sql_compare_lex_op(&a, &b, SqlOp::Ne));
    
    // Refutes
    assert!(!sql_compare_lex_op(&a, &b, SqlOp::Lte));
    assert!(!sql_compare_lex_op(&a, &b, SqlOp::Lt));
    assert!(!sql_compare_lex_op(&a, &b, SqlOp::Eq));
}

quickcheck! {
    #[ignore = "e2e"]
    fn prop_compare_string_eq(x: String) -> TestResult {
        if !x.is_ascii() {
            return TestResult::discard();
        }
        let key = Key::from([0; 32]);
        let a = key.encrypt(x.as_str()).unwrap();
        let b = key.encrypt(x.as_str()).unwrap();

        TestResult::from_bool(sql_compare_lex_op(&a, &b, SqlOp::Eq))
    }
}
