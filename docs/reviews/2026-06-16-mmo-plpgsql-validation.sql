-- GF(2^128) doubling σ(x) = 2·x, reduction poly x^128+x^7+x^2+x+1 (0x87),
-- big-endian 16-byte field element. byte-wise shift-left-1 + conditional XOR.
CREATE OR REPLACE FUNCTION gf128_double(x bytea) RETURNS bytea AS $$
DECLARE r bytea := x; carry int := 0; nc int; i int; topbit int;
BEGIN
  topbit := (get_byte(x,0) >> 7) & 1;
  FOR i IN REVERSE 15..0 LOOP
    nc := (get_byte(r,i) >> 7) & 1;
    r := set_byte(r, i, ((get_byte(r,i) << 1) | carry) & 255);
    carry := nc;
  END LOOP;
  IF topbit = 1 THEN
    r := set_byte(r, 15, get_byte(r,15) # 135);  -- ^ 0x87
  END IF;
  RETURN r;
END; $$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION xor16(a bytea, b bytea) RETURNS bytea AS $$
DECLARE r bytea := a; i int;
BEGIN
  FOR i IN 0..15 LOOP r := set_byte(r, i, get_byte(a,i) # get_byte(b,i)); END LOOP;
  RETURN r;
END; $$ LANGUAGE plpgsql IMMUTABLE;

-- BHKR σ-MMO 1-bit hash: m = σ(f) ⊕ nonce; H = lsb(π(m)) ⊕ lsb(m).
-- π = AES-128-ECB under the fixed public key "ORE-rs.v2.H-pi.1".
CREATE OR REPLACE FUNCTION mmo_hash_bit(f bytea, nonce bytea) RETURNS int AS $$
DECLARE m bytea; pim bytea;
BEGIN
  m := xor16(gf128_double(f), nonce);
  pim := encrypt(m, 'ORE-rs.v2.H-pi.1'::bytea, 'aes-ecb/pad:none');
  RETURN (get_byte(pim,0) & 1) # (get_byte(m,0) & 1);
END; $$ LANGUAGE plpgsql IMMUTABLE;

WITH v(data, nonce, expected) AS (VALUES
  ('\x00070e151c232a31383f464d545b6269'::bytea,'\x010e1b2835424f5c697683909daab7c4'::bytea,1),
  ('\x1f262d343b424950575e656c737a8188'::bytea,'\x121f2c394653606d7a8794a1aebbc8d5'::bytea,0),
  ('\x3e454c535a61686f767d848b9299a0a7'::bytea,'\x23303d4a5764717e8b98a5b2bfccd9e6'::bytea,0),
  ('\x5d646b727980878e959ca3aab1b8bfc6'::bytea,'\x34414e5b6875828f9ca9b6c3d0ddeaf7'::bytea,0),
  ('\x7c838a91989fa6adb4bbc2c9d0d7dee5'::bytea,'\x45525f6c798693a0adbac7d4e1eefb08'::bytea,0),
  ('\x9ba2a9b0b7bec5ccd3dae1e8eff6fd04'::bytea,'\x5663707d8a97a4b1becbd8e5f2ff0c19'::bytea,1),
  ('\xbac1c8cfd6dde4ebf2f900070e151c23'::bytea,'\x6774818e9ba8b5c2cfdce9f603101d2a'::bytea,0),
  ('\xd9e0e7eef5fc030a11181f262d343b42'::bytea,'\x7885929facb9c6d3e0edfa0714212e3b'::bytea,0),
  ('\xf8ff060d141b222930373e454c535a61'::bytea,'\x8996a3b0bdcad7e4f1fe0b1825323f4c'::bytea,0),
  ('\x171e252c333a41484f565d646b727980'::bytea,'\x9aa7b4c1cedbe8f5020f1c293643505d'::bytea,0),
  ('\x363d444b525960676e757c838a91989f'::bytea,'\xabb8c5d2dfecf90613202d3a4754616e'::bytea,1),
  ('\x555c636a71787f868d949ba2a9b0b7be'::bytea,'\xbcc9d6e3f0fd0a1724313e4b5865727f'::bytea,0)
)
SELECT count(*) AS total,
       count(*) FILTER (WHERE mmo_hash_bit(data,nonce) = expected) AS matches,
       count(*) FILTER (WHERE mmo_hash_bit(data,nonce) <> expected) AS mismatches
FROM v;
