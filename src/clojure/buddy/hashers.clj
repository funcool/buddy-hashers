;; Copyright 2013-2015 Andrey Antukh <niwi@niwi.nz>
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

(ns buddy.hashers
  (:require [buddy.core.codecs :refer :all]
            [buddy.core.hash :as hash]
            [buddy.core.nonce :as nonce]
            [buddy.core.bytes :as bytes]
            [clojure.string :as str]
            [clojurewerkz.scrypt.core :as scrypt])
  (:import org.bouncycastle.crypto.digests.SHA1Digest
           org.bouncycastle.crypto.digests.SHA256Digest
           org.bouncycastle.crypto.digests.SHA3Digest
           org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
           buddy.impl.bcrypt.BCrypt))

(java.security.Security/addProvider
 (org.bouncycastle.jce.provider.BouncyCastleProvider.))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Constants
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def ^:dynamic *default-iterations*
  {:pbkdf2+sha1 100000
   :pbkdf2+sha256 100000
   :pbkdf2+sha3_256 5000
   :bcrypt+sha512 12
   :scrypt {:cpucost 65536
            :memcost 8}})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Impl Interface
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmulti parse-password
  "Parse password from string to parts."
  (fn [encryptedpassword]
    (-> encryptedpassword
        (str/split #"\$")
        (first)
        (keyword))))

(defmulti derive-password
  "Derive key depending on algorithm."
  :algorithm)

(defmulti check-password
  "Password verification implementation."
  :algorithm)

(defmulti format-password
  "Format password depending on algorithm."
  :algorithm)

(defmulti must-update?
  "Check if the current password configuration
  is succeptible to be updatable."
  :algorithm)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Key Derivation
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod derive-password :pbkdf2+sha1
  [{:keys [algorithm password salt iterations] :as pwdparams}]
  (let [salt (->byte-array (or salt (nonce/random-bytes 12)))
        iterations (or iterations (get *default-iterations* algorithm))
        pgen (doto (PKCS5S2ParametersGenerator. (SHA1Digest.))
               (.init password salt iterations))
        password (.getKey (.generateDerivedParameters pgen 160))]
    {:algorithm algorithm
     :password password
     :salt salt
     :iterations iterations}))

(defmethod derive-password :pbkdf2+sha256
  [{:keys [algorithm password salt iterations] :as pwdparams}]
  (let [salt (->byte-array (or salt (nonce/random-bytes 12)))
        iterations (or iterations (get *default-iterations* algorithm))
        pgen (doto (PKCS5S2ParametersGenerator. (SHA256Digest.))
               (.init password salt iterations))
        password (.getKey (.generateDerivedParameters pgen 160))]
    {:algorithm algorithm
     :password password
     :salt salt
     :iterations iterations}))

(defmethod derive-password :pbkdf2+sha3_256
  [{:keys [algorithm password salt iterations] :as pwdparams}]
  (let [salt (->byte-array (or salt (nonce/random-bytes 12)))
        iterations (or iterations (get *default-iterations* algorithm))
        pgen (doto (PKCS5S2ParametersGenerator. (SHA3Digest. 256))
               (.init password salt iterations))
        password (.getKey (.generateDerivedParameters pgen 256))]
    {:algorithm algorithm
     :password password
     :salt salt
     :iterations iterations}))

(defmethod derive-password :bcrypt+sha512
  [{:keys [algorithm password salt iterations] :as pwdparams}]
  (let [salt (->byte-array (or salt (nonce/random-bytes 12)))
        iterations (or iterations (get *default-iterations* algorithm))
        iv (BCrypt/gensalt iterations)
        pwd (-> password
                (bytes/concat salt)
                (hash/sha512)
                (bytes->hex)
                (BCrypt/hashpw iv)
                (str->bytes))]
    {:algorithm algorithm
     :iterations iterations
     :salt salt
     :password pwd}))

(defmethod derive-password :scrypt
  [{:keys [algorithm password salt cpucost memcost parallelism] :as pwdparams}]
  (let [salt (->byte-array (or salt (nonce/random-bytes 12)))
        cpucost (or cpucost (get-in *default-iterations* [:scrypt :cpucost]))
        memcost (or memcost (get-in *default-iterations* [:scrypt :memcost]))
        parallelism (or parallelism 1)
        password (-> (bytes/concat salt password salt)
                     (bytes->hex)
                     (scrypt/encrypt cpucost memcost parallelism)
                     (str->bytes))]
    {:algorithm algorithm
     :cpucost cpucost
     :memcost memcost
     :parallelism parallelism
     :password password
     :salt salt}))

(defmethod derive-password :sha256
  [{:keys [algorithm password salt] :as pwdparams}]
  (let [salt (->byte-array (or salt (nonce/random-bytes 12)))
        password (-> (bytes/concat password salt)
                     (hash/sha256))]
    {:algorithm :sha256
     :password password
     :salt salt}))

(defmethod derive-password :md5
  [{:keys [algorithm password salt] :as pwdparams}]
  (let [salt (->byte-array (or salt (nonce/random-bytes 12)))
        password (-> (bytes/concat password salt)
                     (hash/md5))]
    {:algorithm :md5
     :password password
     :salt salt}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Key Verification
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod check-password :bcrypt+sha512
  [pwdparams attempt]
  (let [candidate (-> (bytes/concat attempt (:salt pwdparams))
                      (hash/sha512))]
    (BCrypt/checkpw (bytes->hex candidate)
                    (bytes->str (:password pwdparams)))))

(defmethod check-password :scrypt
  [pwdparams attempt]
  (let [salt (:salt pwdparams)
        candidate (bytes/concat salt attempt salt)]
    (scrypt/verify (bytes->hex candidate)
                   (bytes->str (:password pwdparams)))))

(defmethod check-password :default
  [pwdparams attempt]
  (let [candidate (-> (assoc pwdparams :password attempt)
                      (derive-password))]
    (bytes/equals? (:password pwdparams)
                   (:password candidate))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Key Formatting
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod format-password :scrypt
  [{:keys [password salt cpucost memcost parallelism]}]
  (let [salt (bytes->hex salt)
        password (bytes->hex password)]
    (format "scrypt$%s$%s$%s$%s$%s" salt cpucost memcost parallelism password)))

(defmethod format-password :default
  [{:keys [algorithm password salt iterations]}]
  (let [algorithmname (name algorithm)
        salt (bytes->hex salt)
        password (bytes->hex password)]
    (if (nil? iterations)
      (format "%s$%s$%s" algorithmname salt password)
      (format "%s$%s$%s$%s" algorithmname salt iterations password))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Key Parsing
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod parse-password :scrypt
  [encryptedpassword]
  (let [[algorithm salt cc mc pll password] (str/split encryptedpassword #"\$")
        algorithm (keyword algorithm)]
    {:algorithm algorithm
     :salt (hex->bytes salt)
     :password (hex->bytes password)
     :cpucost (Integer/parseInt cc)
     :memcost (Integer/parseInt mc)
     :parallelism (Integer/parseInt pll)}))

(defmethod parse-password :sha256
  [encryptedpassword]
  (let [[algorithm salt password] (str/split encryptedpassword #"\$")
        algorithm (keyword algorithm)]
    {:algorithm algorithm
     :salt (hex->bytes salt)
     :password (hex->bytes password)}))

(defmethod parse-password :md5
  [encryptedpassword]
  (let [[algorithm salt password] (str/split encryptedpassword #"\$")
        algorithm (keyword algorithm)]
    {:algorithm algorithm
     :salt (hex->bytes salt)
     :password (hex->bytes password)}))

(defmethod parse-password :default
  [encryptedpassword]
  (let [[algorithm salt iterations password] (str/split encryptedpassword #"\$")
        algorithm (keyword algorithm)]
    {:algorithm algorithm
     :salt (hex->bytes salt)
     :password (hex->bytes password)
     :iterations (Integer/parseInt iterations)}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Update Algorithm
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod must-update? :default
  [{:keys [algorithm iterations]}]
  (let [desired-iterations (get *default-iterations* algorithm)]
    (and desired-iterations (> desired-iterations iterations))))

(defmethod must-update? :scrypt
  [{:keys [algorithm memcost cpucost]}]
  (let [desired-memcost (get-in *default-iterations* [:scrypt :memcost])
        desired-cpucost (get-in *default-iterations* [:scrypt :cpucost])]
    (and desired-cpucost
         desired-memcost
         (or (> desired-memcost memcost)
             (> desired-cpucost cpucost)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Public Api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn encrypt
  "Encrypts a raw string password."
  ([password] (encrypt password {}))
  ([password options]
   (let [algorithm (:algorithm options :bcrypt+sha512)
         pwdparams (assoc options
                          :algorithm algorithm
                          :password (str->bytes password))]
     (-> (derive-password pwdparams)
         (format-password)))))

(defn check
  "Check if a unencrypted password matches
  with another encrypted password."
  ([attempt encrypted]
   (check attempt encrypted {}))
  ([attempt encrypted {:keys [limit setter prefered]}]
   (when (and attempt encrypted)
     (let [pwdparams (parse-password encrypted)]
       (if (and (set? limit) (not (contains? limit (:algorithm pwdparams))))
         false
         (let [attempt (str->bytes attempt)
               result (check-password pwdparams attempt)]
           (when (and result (fn? setter) (must-update? pwdparams))
             (setter attempt))
           result))))))
