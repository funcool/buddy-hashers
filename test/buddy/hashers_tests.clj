;; Copyright 2014-2015 Andrey Antukh <niwi@niwi.nz>
;;
;; Licensed under the Apache License, Version 2.0 (the "License")
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

(ns buddy.hashers-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :refer :all]
            [buddy.hashers :as hashers]))

(deftest buddy-hashers
  (let [pwd "my-test-password"]
    (are [alg]
        (let [result (hashers/encrypt pwd {:algorithm alg})]
          (hashers/check pwd result))
      :pbkdf2+sha1
      :pbkdf2+sha256
      :pbkdf2+sha3_256
      :bcrypt+sha512
      :bcrypt+sha384
      :scrypt
      :sha256
      :md5)))

(deftest buddy-hashers
  (let [pwd "my-test-password"]
    (are [alg]
        (let [result (hashers/encrypt pwd {:alg alg})]
          (hashers/check pwd result))
      :pbkdf2+sha1
      :pbkdf2+sha256
      :pbkdf2+sha3_256
      :bcrypt+sha512
      :bcrypt+sha384
      :scrypt
      :sha256
      :md5)))

(deftest buddy-hashers-with-salt
  (let [pwd "my-test-password"
        salt "saltysalted"]
    (are [alg]
        (let [result (hashers/encrypt pwd {:salt salt :algorithm alg})]
          (hashers/check pwd result))
      :pbkdf2+sha1
      :pbkdf2+sha256
      :pbkdf2+sha3_256
      :bcrypt+sha512
      :bcrypt+sha384
      :scrypt
      :sha256
      :md5)))

(deftest confirm-check-failure
  (let [pwd-good "my-test-password"
        pwd-bad "my-text-password"]
    (are [alg]
        (let [result (hashers/encrypt pwd-good {:algorithm alg})]
          (not (hashers/check pwd-bad result)))
      :pbkdf2+sha1
      :pbkdf2+sha256
      :pbkdf2+sha3_256
      :bcrypt+sha512
      :bcrypt+sha384
      :scrypt
      :sha256
      :md5)))

(deftest buddy-hashers-nil
  (let [pwd "my-test-password"
        result (hashers/encrypt pwd {:algorithm :pbkdf2+sha256})]
    (is (nil? (hashers/check nil result)))
    (is (nil? (hashers/check pwd nil)))
    (is (nil? (hashers/check nil nil)))))

(deftest algorithm-embedded-in-hash
  (let [pwd "my-test-password"]
    (are [alg]
        (-> (hashers/encrypt pwd {:algorithm alg})
            (.startsWith (name alg)))
      :pbkdf2+sha1
      :pbkdf2+sha256
      :pbkdf2+sha3_256
      :bcrypt+sha512
      :bcrypt+sha384
      :scrypt
      :sha256
      :md5)))

;; Confirm that the algorithm used is always embedded at the
;; start of the hash, and that the salt is also appended (after
;; being converted to their byte values)

(deftest received-salt-embedded-in-hash
  (let [pwd "my-test-password"
        salt "abcdefgh"]
    (are [alg]
        (-> (hashers/encrypt pwd {:algorithm alg :salt salt})
            (.startsWith (str (name alg) "$" (-> salt str->bytes bytes->hex))))
      :pbkdf2+sha1
      :pbkdf2+sha256
      :pbkdf2+sha3_256
      :bcrypt+sha512
      :bcrypt+sha384
      :scrypt
      :sha256
      :md5)))

(deftest limit-available-algorithms
  (let [pwd (hashers/encrypt "hello" {:algorithm :md5})
        limit #{:pbkdf2+sha256 :bcrypt+sha512}]
    (is (hashers/check "hello" pwd))
    (is (not (hashers/check "hello" pwd {:limit limit})))))

(deftest setter-called
  (let [pwd (hashers/encrypt "hello" {:algorithm :bcrypt+sha512
                                      :iterations 10})
        p (promise)]
    (is (hashers/check "hello" pwd {:setter #(deliver p %)}))
    (is (= (deref p 10 nil) "hello"))))

(deftest possible-regressions-checker
  (let [pbkdf2+sha1 "pbkdf2+sha1$fcf7c2e5848193f91d8a5a40$100000$b499843df692e02be67e534f8592a0785927843a"
        pbkdf2+sha256b "pbkdf2+sha256b$7d0994313982465d82372493$100000$98c4b3043b30622917516e97d1c6bd9936337e8c"
        pbkdf2+sha256 "pbkdf2+sha256$d4043ce1e9e1f9eb9a198b54$100000$71526da5155651ed0eea37d13f728e802c54cf2a3e205b0dbbbfd1f2f169d5a3"
        pbkdf2+sha3_256 "pbkdf2+sha3_256$1278c96b4e68b98c633041dc$5000$d89f67636fec62cdd8379f8ff9305bece38f09b20659916d41cf91eacd91a85b"
        scrypt "scrypt$f54d4b5a1e8d8e63c82e1553$65536$8$1$24733024313030383031246850416d5378645243726664336350546b5a4c7330413d3d243448376945454c47395155492f2b477a42735a582f76554f3345495248656c6939734a73516c356e6571413d"
        sha256 "sha256$bbac53106f8ce4f8c2d78f86$2182339b43ed1546b21488922c2516b64917025084577b33fc49357d9dd2c673"
        bcrypt+sha512 "bcrypt+sha512$680bf9ad0bf9f8249bfebb85$12$243261243132244b4e2e4e456650704558323964686e6c64644f4b73656a6879584f635a4f6b7778596132475036772e6c2e784f49596631556f7679"
        bcrypt+sha384 "bcrypt+sha384$fe8d44009321dbd07984c4a1$12$243261243132246e71754753563849517668706e774e6f75736e4f6f2e2e6e2e75762e7274364b6d3057634d737477443869374b744b7251526e7553"]
    (is (hashers/check "test" pbkdf2+sha1))
    (is (hashers/check "test" pbkdf2+sha256b))
    (is (hashers/check "test" pbkdf2+sha256))
    (is (hashers/check "test" pbkdf2+sha3_256))
    (is (hashers/check "test" scrypt))
    (is (hashers/check "test" sha256))
    (is (hashers/check "test" bcrypt+sha512))
    (is (hashers/check "test" bcrypt+sha384))
    ))

(deftest debug-time-bench
  (let [pwd "my-test-password"]
    (are [alg]
        (do
          (println alg)
          (time (hashers/encrypt pwd {:algorithm alg}))
          true)
      :pbkdf2+sha1
      :pbkdf2+sha256
      :pbkdf2+sha3_256
      :bcrypt+sha512
      :bcrypt+sha384
      :scrypt
      :sha256
      :md5)))

