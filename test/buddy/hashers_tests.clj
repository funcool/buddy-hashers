;; Copyright 2014-2016 Andrey Antukh <niwi@niwi.nz>
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
            [buddy.core.nonce :as nonce]
            [buddy.core.bytes :as bytes]
            [buddy.core.codecs :as codecs]
            [buddy.hashers :as hashers]))

(deftest buddy-hashers
  (let [pwd "my-test-password"]
    (are [alg]
        (let [result (hashers/encrypt pwd {:alg alg})]
          (hashers/check pwd result))
      :pbkdf2+sha1
      :pbkdf2+sha256
      :pbkdf2+sha512
      :pbkdf2+sha3_256
      :pbkdf2+blake2b-512
      :bcrypt+sha512
      :bcrypt+sha384
      :bcrypt+blake2b-512
      :scrypt)))

(deftest buddy-hashers
  (let [pwd "my-test-password"]
    (are [alg]
        (let [result (hashers/encrypt pwd {:alg alg})]
          (hashers/check pwd result))
      :pbkdf2+sha1
      :pbkdf2+sha256
      :pbkdf2+sha512
      :pbkdf2+sha3_256
      :pbkdf2+blake2b-512
      :bcrypt+sha512
      :bcrypt+sha384
      :bcrypt+blake2b-512
      :scrypt)))

(deftest confirm-check-failure
  (let [pwd-good "my-test-password"
        pwd-bad "my-text-password"]
    (are [alg]
        (let [result (hashers/encrypt pwd-good {:alg alg})]
          (not (hashers/check pwd-bad result)))
      :pbkdf2+sha1
      :pbkdf2+sha256
      :pbkdf2+sha512
      :pbkdf2+sha3_256
      :pbkdf2+sha3-256
      :pbkdf2+blake2b-512
      :bcrypt+sha512
      :bcrypt+sha384
      :bcrypt+blake2b-512
      :scrypt)))

(deftest buddy-hashers-nil
  (let [pwd "my-test-password"
        result (hashers/encrypt pwd {:alg :pbkdf2+sha256})]
    (is (nil? (hashers/check nil result)))
    (is (nil? (hashers/check pwd nil)))
    (is (nil? (hashers/check nil nil)))))

(deftest algorithm-embedded-in-hash
  (let [pwd "my-test-password"]
    (are [alg]
        (-> (hashers/encrypt pwd {:alg alg})
            (.startsWith (name alg)))
      :pbkdf2+sha1
      :pbkdf2+sha256
      :pbkdf2+sha512
      :pbkdf2+sha3_256
      :pbkdf2+sha3-256
      :pbkdf2+blake2b-512
      :bcrypt+sha512
      :bcrypt+sha384
      :bcrypt+blake2b-512
      :scrypt)))

;; Confirm that the algorithm used is always embedded at the
;; start of the hash, and that the salt is also appended (after
;; being converted to their byte values)

(deftest received-salt-embedded-in-hash
  (let [pwd "my-test-password"
        salt (nonce/random-bytes 16)]
    (are [alg]
        (-> (hashers/encrypt pwd {:alg alg :salt salt})
            (.startsWith (str (name alg) "$" ( bytes->hex salt))))
      :pbkdf2+sha1
      :pbkdf2+sha256
      :pbkdf2+sha512
      :pbkdf2+sha3_256
      :pbkdf2+sha3-256
      :pbkdf2+blake2b-512
      :bcrypt+sha512
      :bcrypt+sha384
      :bcrypt+blake2b-512
      :scrypt)))

(deftest limit-available-algorithms
  (let [pwd (hashers/encrypt "hello" {:alg :scrypt})
        limit #{:pbkdf2+sha256 :bcrypt+sha512}]
    (is (hashers/check "hello" pwd))
    (is (not (hashers/check "hello" pwd {:limit limit})))))

(deftest update-policy-generic
  (let [pwd (hashers/encrypt "hello" {:alg :bcrypt+sha512
                                      :iterations 10})
        p (promise)]
    (is (hashers/check "hello" pwd {:setter #(deliver p %)}))
    (is (= (deref p 10 nil) "hello"))))

(deftest update-policy-for-pbkdf2+sha256
  (let [pwd-legacy "pbkdf2+sha256$7d0994313982465d82372493$100000$98c4b3043b30622917516e97d1c6bd9936337e8c"
        pwd-new1 "pbkdf2+sha256$b676896c5e9ab9e21b7feafb0d1b8a1b$100000$7af67cae17babcf5cfc20f4f95878b9477023b2797a0e6942aeef567cd4bf1b2"
        pwd-new2 (hashers/encrypt "test" {:alg :pbkdf2+sha256})
        p1 (promise)
        p2 (promise)
        p3 (promise)]
    (is (hashers/check "test" pwd-legacy {:setter #(deliver p1 %)}))
    (is (hashers/check "test" pwd-new1 {:setter #(deliver p2 %)}))
    (is (hashers/check "test" pwd-new2 {:setter #(deliver p3 %)}))
    (is (= (deref p1 10 nil) "test"))
    (is (= (deref p2 10 nil) nil))
    (is (= (deref p3 10 nil) nil))))

(deftest update-policy-for-bcrypt+sha512
  (let [pwd-legacy "bcrypt+sha512$680bf9ad0bf9f8249bfebb85$12$243261243132244b4e2e4e456650704558323964686e6c64644f4b73656a6879584f635a4f6b7778596132475036772e6c2e784f49596631556f7679"
        pwd-new "bcrypt+sha512$b932bf208c7f3ecb563eebe89c39115b$12$bc3633d1f07c47edd91f0e7cf5649b040ea868cec63cda31"
        p1 (promise)
        p2 (promise)]
    (is (hashers/check "test" pwd-legacy {:setter #(deliver p1 %)}))
    (is (hashers/check "test" pwd-new {:setter #(deliver p2 %)}))
    (is (= (deref p1 10 nil) "test"))
    (is (= (deref p2 10 nil) nil))))

(deftest possible-regressions-checker
  (let [pbkdf2+sha1 "pbkdf2+sha1$fcf7c2e5848193f91d8a5a40$100000$b499843df692e02be67e534f8592a0785927843a"
        pbkdf2+sha256-legacy "pbkdf2+sha256$7d0994313982465d82372493$100000$98c4b3043b30622917516e97d1c6bd9936337e8c"
        pbkdf2+sha256 "pbkdf2+sha256$092c7d26206ae9641d225ca432a9efcf$100000$76417ba855c352750319ae649141082bfa83e18ba3a4937580ae7d0226168c6a"
        pbkdf2+sha512 "pbkdf2+sha512$50577ebbbe53552a270598fd$100000$ee0b82c8887fc4bac8e8a28a785e2c7d679fc87a4c42478302ae40acad84aae77fdd2bce57b75595250c1a0226dbbdc4b94954ec61c7d2188d82ea15bce67af5"
        pbkdf2+sha3_256 "pbkdf2+sha3_256$1278c96b4e68b98c633041dc$5000$d89f67636fec62cdd8379f8ff9305bece38f09b20659916d41cf91eacd91a85b"
        pbkdf2+sha3-256 "pbkdf2+sha3-256$1278c96b4e68b98c633041dc$5000$d89f67636fec62cdd8379f8ff9305bece38f09b20659916d41cf91eacd91a85b"
        pbkdf2+blake2b-512 "pbkdf2+blake2b-512$1a26daa54a09150de9f5a053$5000$2fe5dde2355a179f88969218466cd587681af2ce7d6de07080d94efab7cec9e091b7b1c3a34311ff72a3a883f261619b67583c1742f661bb3ab65bc4402fd4c1"
        scrypt "scrypt$f54d4b5a1e8d8e63c82e1553$65536$8$1$24733024313030383031246850416d5378645243726664336350546b5a4c7330413d3d243448376945454c47395155492f2b477a42735a582f76554f3345495248656c6939734a73516c356e6571413d"
        sha256 "sha256$bbac53106f8ce4f8c2d78f86$2182339b43ed1546b21488922c2516b64917025084577b33fc49357d9dd2c673"
        bcrypt+blake2b-512 "bcrypt+blake2b-512$95d0488b2b69c79d4f48ab39338c322e$12$40a4ef31b6dd390b27bd6fc3c2fdeabfb1db85c9bef25c22"
        bcrypt+sha512-legacy "bcrypt+sha512$680bf9ad0bf9f8249bfebb85$12$243261243132244b4e2e4e456650704558323964686e6c64644f4b73656a6879584f635a4f6b7778596132475036772e6c2e784f49596631556f7679"
        bcrypt+sha512 "bcrypt+sha512$b932bf208c7f3ecb563eebe89c39115b$12$bc3633d1f07c47edd91f0e7cf5649b040ea868cec63cda31"
        bcrypt+sha384 "bcrypt+sha384$5c3b8cc880e0dd91520a900a8c8c6223$12$fa6e0a810b81b04634b19311e77eb00ba1d0f12c570adafa"]
    (is (hashers/check "test" pbkdf2+sha1))
    (is (hashers/check "test" pbkdf2+sha256))
    (is (hashers/check "test" pbkdf2+sha256-legacy))
    (is (hashers/check "test" pbkdf2+sha512))
    (is (hashers/check "test" pbkdf2+sha3_256))
    (is (hashers/check "test" pbkdf2+sha3-256))
    (is (hashers/check "test" scrypt))
    (is (hashers/check "test" pbkdf2+blake2b-512))
    (is (hashers/check "test" bcrypt+sha512-legacy))
    (is (hashers/check "test" bcrypt+sha512))
    (is (hashers/check "test" bcrypt+sha384))
    (is (hashers/check "test" bcrypt+blake2b-512))
    ))

(deftest debug-time-bench
  (let [pwd "my-test-password"]
    (are [alg]
        (do
          (println alg)
          (time (hashers/encrypt pwd {:alg alg}))
          true)
      :pbkdf2+sha1
      :pbkdf2+sha256
      :pbkdf2+sha512
      :pbkdf2+sha3_256
      :pbkdf2+sha3-256
      :pbkdf2+blake2b-512
      :bcrypt+sha512
      :bcrypt+sha384
      :bcrypt+blake2b-512
      :scrypt)))

