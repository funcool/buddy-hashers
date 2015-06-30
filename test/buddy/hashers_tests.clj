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

