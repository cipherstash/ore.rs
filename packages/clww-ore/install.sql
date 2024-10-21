CREATE OR REPLACE FUNCTION __cllw_compare(a bytea, b bytea) 
RETURNS int AS $$
DECLARE
    len_a INT;
    x BYTEA;
    y BYTEA;
    i INT;
    differing RECORD;
BEGIN
    len_a := LENGTH(a);
    
    -- Iterate over each byte and compare them
    FOR i IN 1..len_a LOOP
        x := SUBSTRING(a FROM i FOR 1);
        y := SUBSTRING(b FROM i FOR 1);
        
        -- Check if there's a difference
        IF x != y THEN
            differing := (x, y);
            EXIT;
        END IF;
    END LOOP;

    -- If a difference is found, compare the bytes as in Rust logic
    IF differing IS NOT NULL THEN
        IF (get_byte(y, 0) + 1) % 256 = get_byte(x, 0) THEN
            RETURN 1;
        ELSE
            RETURN -1;
        END IF;
    ELSE
        RETURN 0;
    END IF;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION cllw_compare(a bytea, b bytea) 
RETURNS int AS $$
DECLARE
    len_a INT;
    len_b INT;
    x BYTEA;
    y BYTEA;
    i INT;
    differing RECORD;
BEGIN
    -- Check if the lengths of the two bytea arguments are the same
    len_a := LENGTH(a);
    len_b := LENGTH(b);
    
    IF len_a != len_b THEN
        RAISE EXCEPTION 'Bytea arguments must have the same length';
    END IF;

    RETURN __cllw_compare(a, b);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cllw_compare_lex(a bytea, b bytea) 
RETURNS int AS $$
DECLARE
    len_a INT;
    len_b INT;
    cmp_result int;
BEGIN
    -- Get the lengths of both bytea inputs
    len_a := LENGTH(a);
    len_b := LENGTH(b);

    RAISE NOTICE 'Length of a: %', len_a;
    RAISE NOTICE 'Length of b: %', len_b;

    -- Handle empty cases
    IF len_a = 0 AND len_b = 0 THEN
        RETURN 0;
    ELSIF len_a = 0 THEN
        RETURN -1;
    ELSIF len_b = 0 THEN
        RETURN 1;
    END IF;

    -- Use the compare_bytea function to compare byte by byte
    cmp_result := __cllw_compare(a, b);

    -- If the comparison returns 'less' or 'greater', return that result
    IF cmp_result = -1 THEN
        RETURN -1;
    ELSIF cmp_result = 1 THEN
        RETURN 1;
    END IF;

    -- If the bytea comparison is 'equal', compare lengths
    IF len_a < len_b THEN
        RETURN 1;
    ELSIF len_a > len_b THEN
        RETURN -1;
    ELSE
        RETURN 0;
    END IF;
END;
$$ LANGUAGE plpgsql;
