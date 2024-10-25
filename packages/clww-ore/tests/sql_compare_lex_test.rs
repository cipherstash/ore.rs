use cllw_ore::{Key, OreCllw8VariableV1};
use postgres::{Client, NoTls};

fn setup_db() -> Client {
    Client::connect("dbname=cllwtest host=localhost user=postgres", NoTls)
        .expect("Failed to connect to database")
}

fn sql_compare_lex(a: &OreCllw8VariableV1, b: &OreCllw8VariableV1) -> i32 {
    let response = setup_db()
        .query("SELECT compare_lex_ore_cllw_8_v1($1, $2)", &[&a, &b])
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
