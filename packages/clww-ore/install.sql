

-- Represents a ciphertext encrypted with the CLLW ORE scheme
-- Each output block is 8-bits
CREATE TYPE ore_cllw_8_v1 AS (
  bytes bytea
);


CREATE OR REPLACE FUNCTION __compare_inner_ore_cllw_8_v1(a ore_cllw_8_v1, b ore_cllw_8_v1) 
RETURNS int AS $$
DECLARE
    len_a INT;
    x BYTEA;
    y BYTEA;
    i INT;
    differing RECORD;
BEGIN
    len_a := LENGTH(a.bytes);
    
    -- Iterate over each byte and compare them
    FOR i IN 1..len_a LOOP
        x := SUBSTRING(a.bytes FROM i FOR 1);
        y := SUBSTRING(b.bytes FROM i FOR 1);
        
        -- Check if there's a difference
        -- TODO: Don't exit right away (constant time)
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


CREATE OR REPLACE FUNCTION compare_ore_cllw_8_v1(a ore_cllw_8_v1, b ore_cllw_8_v1) 
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
    len_a := LENGTH(a.bytes);
    len_b := LENGTH(b.bytes);
    
    IF len_a != len_b THEN
        RAISE EXCEPTION 'Bytea arguments must have the same length';
    END IF;

    RETURN __compare_inner_ore_cllw_8_v1(a, b);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION compare_lex_ore_cllw_8_v1(a ore_cllw_8_v1, b ore_cllw_8_v1)
RETURNS int AS $$
DECLARE
    len_a INT;
    len_b INT;
    cmp_result int;
BEGIN
    -- Get the lengths of both bytea inputs
    len_a := LENGTH(a.bytes);
    len_b := LENGTH(b.bytes);

    -- Handle empty cases
    IF len_a = 0 AND len_b = 0 THEN
        RETURN 0;
    ELSIF len_a = 0 THEN
        RETURN -1;
    ELSIF len_b = 0 THEN
        RETURN 1;
    END IF;

    -- Use the compare_bytea function to compare byte by byte
    cmp_result := __compare_inner_ore_cllw_8_v1(a, b);

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

CREATE OR REPLACE FUNCTION ore_cllw_8_v1_eq(a ore_cllw_8_v1, b ore_cllw_8_v1) RETURNS boolean AS $$
  SELECT compare_ore_cllw_8_v1(a, b) = 0
$$ LANGUAGE SQL;

CREATE OR REPLACE FUNCTION ore_cllw_8_v1_neq(a ore_cllw_8_v1, b ore_cllw_8_v1) RETURNS boolean AS $$
  SELECT compare_ore_cllw_8_v1(a, b) <> 0
$$ LANGUAGE SQL;

CREATE OR REPLACE FUNCTION ore_cllw_8_v1_lt(a ore_cllw_8_v1, b ore_cllw_8_v1) RETURNS boolean AS $$
  SELECT compare_ore_cllw_8_v1(a, b) = -1
$$ LANGUAGE SQL;

CREATE OR REPLACE FUNCTION ore_cllw_8_v1_lte(a ore_cllw_8_v1, b ore_cllw_8_v1) RETURNS boolean AS $$
  SELECT compare_ore_cllw_8_v1(a, b) != 1
$$ LANGUAGE SQL;

CREATE OR REPLACE FUNCTION ore_cllw_8_v1_gt(a ore_cllw_8_v1, b ore_cllw_8_v1) RETURNS boolean AS $$
  SELECT compare_ore_cllw_8_v1(a, b) = 1
$$ LANGUAGE SQL;

CREATE OR REPLACE FUNCTION ore_cllw_8_v1_gte(a ore_cllw_8_v1, b ore_cllw_8_v1) RETURNS boolean AS $$
  SELECT compare_ore_cllw_8_v1(a, b) != -1
$$ LANGUAGE SQL;

CREATE OPERATOR = (
  PROCEDURE="ore_cllw_8_v1_eq",
  LEFTARG=ore_cllw_8_v1,
  RIGHTARG=ore_cllw_8_v1,
  NEGATOR = <>,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES,
  MERGES
);

CREATE OPERATOR <> (
  PROCEDURE="ore_cllw_8_v1_neq",
  LEFTARG=ore_cllw_8_v1,
  RIGHTARG=ore_cllw_8_v1,
  NEGATOR = =,
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES,
  MERGES
);

CREATE OPERATOR > (
  PROCEDURE="ore_cllw_8_v1_gt",
  LEFTARG=ore_cllw_8_v1,
  RIGHTARG=ore_cllw_8_v1,
  NEGATOR = <=,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel,
  HASHES,
  MERGES
);

CREATE OPERATOR < (
  PROCEDURE="ore_cllw_8_v1_lt",
  LEFTARG=ore_cllw_8_v1,
  RIGHTARG=ore_cllw_8_v1,
  NEGATOR = >=,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel,
  HASHES,
  MERGES
);

CREATE OPERATOR >= (
  PROCEDURE="ore_cllw_8_v1_gte",
  LEFTARG=ore_cllw_8_v1,
  RIGHTARG=ore_cllw_8_v1,
  NEGATOR = <,
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel,
  HASHES,
  MERGES
);

CREATE OPERATOR <= (
  PROCEDURE="ore_cllw_8_v1_lte",
  LEFTARG=ore_cllw_8_v1,
  RIGHTARG=ore_cllw_8_v1,
  NEGATOR = >,
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel,
  HASHES,
  MERGES
);

CREATE OPERATOR FAMILY ore_cllw_8_v1_btree_ops USING btree;
CREATE OPERATOR CLASS ore_cllw_8_v1_btree_ops DEFAULT FOR TYPE ore_cllw_8_v1 USING btree FAMILY ore_cllw_8_v1_btree_ops  AS
        OPERATOR 1 <,
        OPERATOR 2 <=,
        OPERATOR 3 =,
        OPERATOR 4 >=,
        OPERATOR 5 >,
        FUNCTION 1 compare_ore_cllw_8_v1(a ore_cllw_8_v1, b ore_cllw_8_v1);
