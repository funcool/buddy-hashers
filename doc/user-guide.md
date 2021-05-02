# User Guide

*buddy-hashers* provides a collection of secure password hashers with
lightweight and extensible abstraction for build powerfull password
authentication processes.

Supported password hashers algorithms:

| Identifier | Can I use it? | Description |
|---|---|---|
| `:bcrypt+blake2b-512` | Recommended | BCrypt password hasher combined with blake2b-512 |
| `:argon2id` | Recommended | Argon2id password hasher |
| `:pbkdf2+blake2b-512` | Yes | Password-Based Key Derivation Function 2 with blake2b-512|
| `:pbkdf2+sha512`   | Yes | Password-Based Key Derivation Function 2 with SHA256 |
| `:pbkdf2+sha3-256` | Yes | Password-Based Key Derivation Function 2 with SHA3-256 |
| `:bcrypt+sha512`   | Yes | BCrypt password hasher combined with sha512 (default) |
| `:pbkdf2+sha256`   | Yes | Password-Based Key Derivation Function 2 with SHA256 |
| `:bcrypt+sha384`   | Yes | BCrypt password hasher combined with sha384 |
| `:pbkdf2+sha1`     | Yes | Password-Based Key Derivation Function 2 (as defined in RFC2898) |
| `:scrypt`          | Yes | Password-Based Key Derivation Function created by Colin Percival |
| `:argon2id`        | Yes | Memory-Hard Key Derivation Function for password hashing and other applications |


## Install

The simplest way to use _buddy-core_ in a clojure project, is by including it in the
dependency vector on your *_project.clj_* file:

```clojure
[buddy/buddy-hashers "1.8.1"]
```

Or deps.edn:

```clojure
buddy/buddy-hashers {:mvn/version "1.8.1"}
```

And is tested under JDK >= 8


## Quick Start

Hashers module consists in two public functions: *derive* and *check*
and both them are located on `buddy.hashers` namespace.

Let start deriving a password:


```clojure
(require '[buddy.hashers :as hashers])

;; Generate hash from plain password
(hashers/derive "secretpassword")
;; => "bcrypt+sha512$4i9sd34m..."

(hashers/verify "secretpassword" "bcrypt+sha512$4i9sd34m...")
;; => {:valid true :update false}
```

If no algorithm is specified, the `:bcrypt+sha512` will be used by
default. **We highly recommend setting your own default for prevent
any unexpected situations when the library changes the default.**

If you want to use a specific one, you can specify it using
the optional options parameter:

```clojure
;; Generate hash from plain password
(hashers/derive "secretpassword" {:alg :pbkdf2+sha256})
;; => "pbkdf2+sha256$4i9sd34m..."

(hashers/verify "secretpassword" "pbkdf2+sha256$4i9sd34m...")
;; => {:valid true :update false}
```

## Advanced options

### Algorithm tunning params

Each algorithm can be tweaked passing additional parameters on the
second argument to *derive* function. And options vary depending on
the used algorithm.

Table that details available options and defaults values:

| Algorithm | Available options | Defaults |
|---|---|---|
| `:bcrypt+blake2b-512` | `:salt`, `:iterations` | iterations=12, salt=(random 16 bytes) |
| `:bcrypt+sha384` | `:salt`, `:iterations` | iterations=12, salt=(random 16 bytes) |
| `:pbkdf2+blake2b-512` | `:salt`, `:iterations` | iterations=50000, salt=(random 12 bytes) |
| `:pbkdf2+sha512` | `:salt`, `:iterations` | iterations=100000, salt=(random 12 bytes) |
| `:pbkdf2+sha3_256` | `:salt`, `:iterations` | iterations=100000, salt=(random 12 bytes) |
| `:pbkdf2+sha1` | `:salt`, `:iterations` | iterations=100000, salt=(random 12 bytes) |
| `:scrypt` | `:salt`, `:cpucost`, `:memcost`, `:parallelism` | salt=(random 12 bytes), cpucost=65536, memcost=8, parallelism=1 |
| `:bcrypt+sha512` | `:salt`, `:iterations` | iterations=12, salt=(random 12 bytes) |
| `:pbkdf2+sha256` | `:salt`, `:iterations` | iterations=100000, salt=(random 12 bytes) |
| `:argon2id` | `:salt`, `:memory`, `:iterations`, `:parallelism` | salt=(random 16 bytes), memory=65536, iterations=2, parallelism=1 |


### Limiting algorithms

Some times you don't want to use all the supported algorithms and you only want
to use a own set of algorithms in the password check process. That can be done
passing additional parameter to the `check` function:

```clojure
(def trusted-algs #{:pbkdf2+sha256 :bcrypt+sha512})

(hashers/verify incoming-pwd derived-pwd {:limit trusted-algs})
```

The `verify` function will return false if the incoming password uses an algorithm
that does not allowed.


### Password updating

Choice a strong algorithm is important thing, but have a good update
password-hashes policy is also very important and usually completelly
forgotten.  The password generated 3 years ago is weaker that one
generated today...

*buddy-hashers* comes with a solution for make this task easier. The returned
object by the `verify` function contains a prop `:update` that indicates
if the password should be updated or not.

It there is an example on how it can be used:

```clojure
(let [result (hashers/verify incoming-pwd derived-pwd)]
  (when (:valid result)
    (when (:update result)
      (do-db-update (hashers/derive incoming-pwd)))))
```


## Source Code

_buddy-hashers_ is open source and can be found on
[github](https://github.com/funcool/buddy-hashers).

You can clone the public repository with this command:

```bash
git clone https://github.com/funcool/buddy-hashers
```


## Run tests

For running tests just execute this:

```bash
lein test
```


## License

_buddy-hashers_ is licensed under Apache 2.0 License. You can see the
complete text of the license on the root of the repository on
`LICENSE` file.
