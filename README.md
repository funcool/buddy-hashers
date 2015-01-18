# buddy-hashers

[![Travis Badge](https://img.shields.io/travis/funcool/buddy-hashers.svg?style=flat)](https://travis-ci.org/funcool/buddy-hashers "Travis Badge")
[![Dependencies Status](http://jarkeeper.com/funcool/buddy-hashers/status.svg)](http://jarkeeper.com/funcool/buddy-hashers)

## Install ##

```clojure
[buddy/buddy-hashers "0.3.0"]
```

## Quick Start ##

Hashers module consists in two public functions: *encrypt* and *check* and both them are
located on `buddy.hashers` namespace.

For start using it, just import it on your namespace:

```clojure
(ns my.app
  (:require [buddy.hashers :as hashers]))
```

Now, choice the algorithm and encrypt your passwords:

```clojure
;; Generate hash from plain password
(hashers/encrypt "secretpassword"))
;; => "bcrypt+sha512$4i9sd34m..."

(hashers/check "secretpassword" "bcrypt+sha512$4i9sd34m..."))
;; => true
```

## Documentation ##

https://funcool.github.io/buddy-hashers/latest/
