use cllw_ore::Key;
use postgres::{Client, NoTls};
use quickcheck::{quickcheck};


fn setup_db() -> Client {
    Client::connect("dbname=cllwtest host=localhost user=postgres", NoTls)
        .expect("Failed to connect to database")
}

fn sql_compare(a: &[u8], b: &[u8]) -> i32 {
    let response = setup_db().query("SELECT cllw_compare($1, $2)", &[&a.as_ref(), &b.as_ref()])
        .expect("Failed to execute query");

    let row = response.get(0)
        .expect("Expected a result");

    row.get(0)
}

fn expect(a: u64, b: u64) -> i32 {
    if a < b {
        return -1;
    } else if a > b {
        return 1;
    } else {
        return 0;
    }
}

quickcheck! {
    fn test_compare_u64_eq(x: u64) -> bool {
        let key = Key::from([0; 32]);
        let a = key.encrypt::<u64>(x);
        let b = key.encrypt::<u64>(x);

        sql_compare(a.as_ref(), b.as_ref()) == 0
    }

    fn test_compare_u64_cmp(a: u64, b: u64) -> bool {
        let key = Key::from([0; 32]);
        let x = key.encrypt::<u64>(a);
        let y = key.encrypt::<u64>(b);

        expect(a, b) == sql_compare(x.as_ref(), y.as_ref())
    }
}