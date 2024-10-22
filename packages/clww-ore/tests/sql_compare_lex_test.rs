use cllw_ore::Key;
use postgres::{Client, NoTls};

fn setup_db() -> Client {
    Client::connect("dbname=cllwtest host=localhost user=postgres", NoTls)
        .expect("Failed to connect to database")
}

fn sql_compare_lex(a: &[u8], b: &[u8]) -> i32 {
    let response = setup_db()
        .query("SELECT ore_cllw_8_v1_compare_lex($1, $2)", &[&a, &b])
        .expect("Failed to execute query");

    let row = response.first().expect("Expected a result");

    row.get(0)
}

#[test]
fn test_compare_string_eq() {
    let key = Key::from([0; 32]);
    let a = key.encrypt("cat").unwrap();
    let b = key.encrypt("cat").unwrap();

    assert_eq!(sql_compare_lex(a.as_ref(), b.as_ref()), 0);
}

#[test]
fn test_compare_string_prefix() {
    let key = Key::from([0; 32]);
    let a = key.encrypt("cat").unwrap();
    let b = key.encrypt("catskills").unwrap();

    assert_eq!(sql_compare_lex(a.as_ref(), b.as_ref()), 1);
}
