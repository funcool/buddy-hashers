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
      :scrypt
      :sha256
      :md5)))
