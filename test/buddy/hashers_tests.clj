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
  (let [plain-password "my-test-password"]
    (is (hashers/check plain-password
                       (hashers/encrypt plain-password)))
    (is (hashers/check plain-password
                       (hashers/encrypt plain-password {:algorithm :pbkdf2+sha1})))
    (is (hashers/check plain-password
                       (hashers/encrypt plain-password {:algorithm :pbkdf2+sha256})))
    (is (hashers/check plain-password
                       (hashers/encrypt plain-password {:algorithm :pbkdf2+sha3_256})))
    (is (hashers/check plain-password
                       (hashers/encrypt plain-password {:algorithm :bcrypt+sha512})))
    (is (hashers/check plain-password
                       (hashers/encrypt plain-password {:algorithm :scrypt})))
    (is (hashers/check plain-password
                       (hashers/encrypt plain-password {:algorithm :sha256})))
    (is (hashers/check plain-password
                       (hashers/encrypt plain-password {:algorithm :md5})))))


(deftest buddy-hashers-with-salt
  (let [plain-password "my-test-password"
        salt           "saltysalted"]
    (is (hashers/check plain-password
                       (hashers/encrypt plain-password {:salt salt})))
    (is (hashers/check plain-password
                       (hashers/encrypt plain-password {:algorithm :pbkdf2+sha1 :salt salt})))
    (is (hashers/check plain-password
                       (hashers/encrypt plain-password {:algorithm :pbkdf2+sha256 :salt salt})))
    (is (hashers/check plain-password
                       (hashers/encrypt plain-password {:algorithm :pbkdf2+sha3_256 :salt salt})))
    (is (hashers/check plain-password
                       (hashers/encrypt plain-password {:algorithm :bcrypt+sha512 :salt salt})))
    (is (hashers/check plain-password
                       (hashers/encrypt plain-password {:algorithm :scrypt :salt salt})))
    (is (hashers/check plain-password
                       (hashers/encrypt plain-password {:algorithm :sha256 :salt salt})))
    (is (hashers/check plain-password
                       (hashers/encrypt plain-password {:algorithm :md5 :salt salt})))))


(deftest confirm-check-failure
  (let [plain-password "my-test-password"
        bad-password   "my-text-password"]
    (is (not (hashers/check bad-password
                            (hashers/encrypt plain-password))))
    (is (not (hashers/check bad-password
                            (hashers/encrypt plain-password {:algorithm :pbkdf2+sha1}))))
    (is (not (hashers/check bad-password
                            (hashers/encrypt plain-password {:algorithm :pbkdf2+sha256}))))
    (is (not (hashers/check bad-password
                            (hashers/encrypt plain-password {:algorithm :pbkdf2+sha3_256}))))
    (is (not (hashers/check bad-password
                            (hashers/encrypt plain-password {:algorithm :bcrypt+sha512}))))
    (is (not (hashers/check bad-password
                            (hashers/encrypt plain-password {:algorithm :scrypt}))))
    (is (not (hashers/check bad-password
                            (hashers/encrypt plain-password {:algorithm :sha256}))))
    (is (not (hashers/check bad-password
                            (hashers/encrypt plain-password {:algorithm :md5}))))))


(deftest buddy-hashers-nil
  (let [plain-password "my-test-password"
        encrypted-password (hashers/encrypt plain-password {:algorithm :pbkdf2+sha256})]
    (is (= nil (hashers/check nil encrypted-password)))
    (is (= nil (hashers/check plain-password nil)))
    (is (= nil (hashers/check nil nil)))))


;;;;
;;;; Tests related to the resulting value's structure
;;;;

(deftest algorithm-embedded-in-hash
  ;; Confirm that the algorithm used is always embedded at the start of the hash
  (let [plain-password "my-test-password"]
    (are [algorithm] (.startsWith (hashers/encrypt plain-password {:algorithm algorithm}) (name algorithm))
                     :pbkdf2+sha1
                     :pbkdf2+sha256
                     :pbkdf2+sha3_256
                     :bcrypt+sha512
                     :scrypt
                     :sha256
                     :md5
                     )))


(deftest received-salt-embedded-in-hash
  (let [plain-password "my-test-password"
        salt           "abcdefgh"]
    ;; Confirm that the algorithm used is always embedded at the start of the hash,
    ;; and that the salt is also appended (after being converted to their byte values)
    (are [algorithm] (.startsWith (hashers/encrypt plain-password {:algorithm algorithm :salt salt})
                                  (str (name algorithm) "$" (-> salt str->bytes bytes->hex)))
                     :pbkdf2+sha1
                     :pbkdf2+sha256
                     :pbkdf2+sha3_256
                     :bcrypt+sha512
                     :scrypt
                     :sha256
                     :md5
                     )))