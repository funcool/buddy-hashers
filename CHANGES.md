# Changelog

## Version 1.7.0

Date: 2020-09-15

- Update buddy-core to 1.9.0
- Add native argon2id.


## Version 1.6.0

Date: 2020-09-15

- Add `verify` function as better alternative to `check`.


## Version 1.5.1

Date: 2020-09-15

- Revert some breaking changes from previous version.


## Version 1.5.0

Date: 2020-09-15

- Update buddy-core to 1.7.1
- Remove unused internal BCrypt impl.
- Remove deprecated `:pbkdf2+sha3_256` alias.
- Fix documentation.

## Version 1.4.0

Date: 2019-06-28

- Update buddy-core to 1.6.0


## Version 1.3.0

Date: 2017-08-29

- Update buddy-core to 1.4.0


## Version 1.2.0

Date: 2017-01-24

- Update buddy-core to 1.2.0


## Version 1.1.0

Date: 2016-11-15

- Update buddy-core to 1.1.1


## Version 1.0.0

Date: 2016-09-01

- Update buddy-core to 1.0.0
- Change versiom scheme to be consistent with buddy-core.


## Version 0.14.0

Date: 2016-04-09

- Update buddy-core to 0.12.1.


## Version 0.13.0

Date: 2016-03-27

- Update buddy-core to 0.11.0.


## Version 0.12.0

Date: 2016-03-26

- The `encrypt` function becomes `derive` (backward compatibile change).
- Update buddy-core to 0.10.0.


## Version 0.11.0

Date: 2016-01-23

- The `:algorithm` parameter is now removed (`:alg` should be used).
- The `:sha256` and `:md5` hashers are removed.
- The randomization of default algorithm introduced in  0.9.x is
  now reverted and the `
- Set clojure 1.8.0 as default clojure version.


## Version 0.10.0

Date: 2016-01-06

- Update buddy-core dependency to 0.9.0.


## Version 0.9.1

Date: 2015-11-28

- Update to buddy-core 0.8.1.


## Version 0.9.0

Date: 2015-11-09

Important notes:

- The `encrypt` function now selects a random algorithm from recommended
  algorithms list instead to have default one. This enables to have additional
  security layer having more than one algorithm to be broken for recover
  all passwords. This behavior is different from previous one and you should
  care about it. If you want the previous behavior, just preselect the
  prefered cipher passing it explicitly to the `encrypt` function.
- The `bcrypt+sha512` hasher strength is improved.
  The previous algorithm is still available for password checking only and
  password update setter will be triggered if password with old algorithm
  is used for checking process.
- The `pbkdf2+sha256` hasher strength is improved.
  A little weakness is discovered in the implementation that decreases the hash
  security from 256 bits to 160 bits (output truncation). This means that
  the old password are at least secure as `pbkdf2+sha1`, that is still
  condsidered secure and widele employed (besides, the sha256 hash output
  truncated to 160 bits is more secure than sha1, so you don't be worried
  about that).
  The hasher algorithm is backward compatible and if you are using the builtin
  helpers for password upgrading it will be automatically triggered if old
  version of password is checked.

Other changes:

- The `pbkdf2+sha3_256` is renamed to `pbkdf2+sha3-256`. This is a backward
  compatible change because the previous alias is still conserved until the next
  release.
- The `md5` and `sha256` hashers has been deprecated and will be removed in the
  next version.
- Add `:pbkdf2+blake2b-512` hasher as part of the recommended password hashers.
- Add `:pbkdf2+sha512` hasher as part of the recommended password hashers.
- Add `:bcrypt+sha384` hasher (for some one that does not like use blake2b-512).
- The `:algorithm` parameter is deprecated in favor of the shorter `:alg`.


## Version 0.8.0

Date: 2015-10-31

- Add the ability to limit the set of allowed algorithms
  to be used in the check process.
- Add the ability to react in case the password has weak
  configuration and rehash it again (and store fresh
  encoded password with updated stronger config).
- Decrease the rounds for :pbkdf2-sha3_256 because
  the previous one was too heavy.


## Version 0.7.0

Date: 2015-09-19

- Set default clojure version to 1.7.0
- Update buddy-core version to 0.7.0


## Version 0.6.0

Date: 2015-06-28

- Update to buddy-core 0.6.0
- Remove buddy-hashers 0.2.x hashers implementation.


## Version 0.5.0

Date: 2015-06-15

- `check` function is now null pointer safe.


## Version 0.4.2

Date: 2015-04-03

- Update buddy-core to 0.5.0


## Version 0.4.1

Date: 2015-03-14

- Update buddy-core from 0.4.0 to 0.4.2


## Version 0.4.0

Date: 2015-02-22

- Update buddy-core dependency version to 0.4.0
- Adapt the code to buddy-core 0.4.0


## Version 0.3.0

Date: 2015-01-18

- First version splitted from monolitic buddy package.
- Add complete refactored version of hashers, more flexible and extensible.
- Add support for pbkdf2+sha256 and pbkdf2+sha3_256 password hasher algorithms.
- Maintain the old namespace for backward compatibility.
