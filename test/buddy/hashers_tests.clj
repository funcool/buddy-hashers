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
            [buddy.hashers :as hashers]
            [buddy.hashers.pbkdf2 :as pbkdf2]
            [buddy.hashers.bcrypt :as bcrypt]
            [buddy.hashers.sha256 :as sha256]
            [buddy.hashers.md5 :as md5]
            [buddy.hashers.scrypt :as scrypt]))

(deftest buddy-hashers-old
  (testing "Test low level api for encrypt/verify pbkdf2"
    (let [plain-password      "my-test-password"
          encrypted-password  (pbkdf2/make-password plain-password)]
      (is (pbkdf2/check-password plain-password encrypted-password))))

  (testing "Test low level api for encrypt/verify sha256"
    (let [plain-password      "my-test-password"
          encrypted-password  (sha256/make-password plain-password)]
      (is (sha256/check-password plain-password encrypted-password))))

  (testing "Test low level api for encrypt/verify md5"
    (let [plain-password      "my-test-password"
          encrypted-password  (md5/make-password plain-password)]
      (is (md5/check-password plain-password encrypted-password))))

  (testing "Test low level api for encrypt/verify bcrypt"
    (let [plain-password      "my-test-password"
          encrypted-password  (bcrypt/make-password plain-password)]
      (is (bcrypt/check-password plain-password encrypted-password))))

  (testing "Test low level api for encrypt/verify scrypt"
    (let [plain-password      "my-test-password"
          encrypted-password  (scrypt/make-password plain-password)]
      (is (scrypt/check-password plain-password encrypted-password)))))

(deftest buddy-hashers
  (let [plain-password "my-test-password"]
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

(deftest buddy-hashers-nil
  (let [plain-password "my-test-password"
        encrypted-password (hashers/encrypt plain-password {:algorithm :pbkdf2+sha256})]
    (is (= nil (hashers/check nil encrypted-password)))
    (is (= nil (hashers/check plain-password nil)))
    (is (= nil (hashers/check nil nil)))))

