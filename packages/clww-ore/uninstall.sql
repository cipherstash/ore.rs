
DROP OPERATOR CLASS IF EXISTS ore_cllw_8_v1_btree_ops USING btree;
DROP OPERATOR FAMILY IF EXISTS ore_cllw_8_v1_btree_ops USING btree;
DROP OPERATOR IF EXISTS = (ore_cllw_8_v1, ore_cllw_8_v1);
DROP OPERATOR IF EXISTS > (ore_cllw_8_v1, ore_cllw_8_v1);
DROP OPERATOR IF EXISTS >= (ore_cllw_8_v1, ore_cllw_8_v1);
DROP OPERATOR IF EXISTS < (ore_cllw_8_v1, ore_cllw_8_v1);
DROP OPERATOR IF EXISTS <= (ore_cllw_8_v1, ore_cllw_8_v1);
DROP OPERATOR IF EXISTS <> (ore_cllw_8_v1, ore_cllw_8_v1);
DROP FUNCTION IF EXISTS ore_cllw_8_v1_eq;
DROP FUNCTION IF EXISTS ore_cllw_8_v1_neq;
DROP FUNCTION IF EXISTS ore_cllw_8_v1_lt;
DROP FUNCTION IF EXISTS ore_cllw_8_v1_lte;
DROP FUNCTION IF EXISTS ore_cllw_8_v1_gt;
DROP FUNCTION IF EXISTS ore_cllw_8_v1_gte;
DROP FUNCTION IF EXISTS compare_ore_cllw_8_v1;
DROP FUNCTION IF EXISTS compare_lex_ore_cllw_8_v1;
DROP FUNCTION IF EXISTS __compare_inner_ore_cllw_8_v1;

DROP TYPE IF EXISTS ore_cllw_8_v1;
