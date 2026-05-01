

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
