

### Miscellaneous

- release


### Features

- impl ToOrderableBytes for i16/i32/i64/f64
- impl ToOrderableBytes for bool
- impl ToOrderableBytes for u8/i8 and u128/i128
- impl ToOrderableBytes for u16/u32/u64
- impl ToOrderableBytes for char and f32

### Miscellaneous

- release

### Refactoring

- introduce ToOrderableBytes trait
- widen i16/i32 numeric impls to [u8; 8]
- rename `numeric` module to `primitive`
- emit native widths for narrow primitives


### Features

- impl ToOrderableBytes for i16/i32/i64/f64
- impl ToOrderableBytes for bool
- impl ToOrderableBytes for u8/i8 and u128/i128
- impl ToOrderableBytes for u16/u32/u64
- impl ToOrderableBytes for char and f32

### Refactoring

- introduce ToOrderableBytes trait
- widen i16/i32 numeric impls to [u8; 8]
- rename `numeric` module to `primitive`
- emit native widths for narrow primitives


### Documentation

- add worked-example walkthrough to README
- foreground the crate's purpose in the README

### Miscellaneous

- add orderable-bytes README and release-plz support
- move hex-literal to dev-deps; add James to authors

### Refactoring

- rename ore-encoders → orderable-bytes; pre_encode → to_orderable_bytes
- rename m/count → mantissa/exponent in strip_trailing_zeros

### Testing

- property tests for strip_trailing_zeros
