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
  (:refer-clojure :exclude [derive])
  (:require [buddy.core.codecs :as codecs]
            [buddy.core.hash :as hash]
            [buddy.core.nonce :as nonce]
            [buddy.core.bytes :as bytes]
            [clojure.string :as str]
            [clojurewerkz.scrypt.core :as scrypt])
  (:import org.bouncycastle.crypto.Digest
           org.bouncycastle.crypto.digests.SHA1Digest
           org.bouncycastle.crypto.digests.SHA256Digest
           org.bouncycastle.crypto.digests.SHA3Digest
           org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
           org.bouncycastle.crypto.generators.BCrypt
           org.bouncycastle.crypto.params.KeyParameter
           java.security.Security))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Constants
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def ^:no-doc ^:static
  +iterations+
  {:pbkdf2+sha1 100000
   :pbkdf2+sha256 100000
   :pbkdf2+sha512 100000
   :pbkdf2+blake2b-512 50000
   :pbkdf2+sha3_256 5000
   :pbkdf2+sha3-256 5000
   :bcrypt+sha512 12
   :bcrypt+sha384 12
   :bcrypt+blake2b-512 12
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

(defn- dispatch
  [opts & args]
  (:alg opts))

(defmulti derive-password
  "Derive key depending on algorithm."
  dispatch)

(defmulti check-password
  "Password verification implementation."
  dispatch)

(defmulti format-password
  "Format password depending on algorithm."
  dispatch)

(defmulti must-update?
  "Check if the current password configuration
  is succeptible to be updatable."
  dispatch)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Key Derivation
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod derive-password :pbkdf2
  [{:keys [alg password salt iterations digest] :as pwdparams}]
  (let [salt (codecs/to-bytes (or salt (nonce/random-bytes 12)))
        alg (keyword (str "pbkdf2+" (name digest)))
        iterations (or iterations (get +iterations+ alg))
        ^Digest digest (hash/resolve-digest-engine digest)
        dsize (* 8 (.getDigestSize digest))
        pgen (doto (PKCS5S2ParametersGenerator. digest)
               (.init password salt iterations))
        ^KeyParameter cparams (.generateDerivedParameters pgen dsize)
        password (.getKey cparams)]
    {:alg alg
     :password password
     :salt salt
     :iterations iterations}))

(defmethod derive-password :pbkdf2+sha1
  [options]
  (derive-password (assoc options :alg :pbkdf2 :digest :sha1)))

(defmethod derive-password :pbkdf2+sha256
  [options]
  (derive-password (assoc options :alg :pbkdf2 :digest :sha256)))

(defmethod derive-password :pbkdf2+sha512
  [options]
  (derive-password (assoc options :alg :pbkdf2 :digest :sha512)))

(defmethod derive-password :pbkdf2+blake2b-512
  [options]
  (derive-password (assoc options :alg :pbkdf2 :digest :blake2b-512)))

(defmethod derive-password :pbkdf2+sha3-256
  [options]
  (derive-password (assoc options :alg :pbkdf2 :digest :sha3-256)))

;; DEPRECATED: this is an alias for :pbkdf2+sha3-256 and should be consdered
;; deprecated. It will be removed in the next version.

(defmethod derive-password :pbkdf2+sha3_256
  [{:keys [alg password salt iterations] :as pwdparams}]
  (let [salt (codecs/to-bytes (or salt (nonce/random-bytes 12)))
        iterations (or iterations (get +iterations+ alg))
        pgen (doto (PKCS5S2ParametersGenerator. (SHA3Digest. 256))
               (.init password salt iterations))
        ^KeyParameter cparams (.generateDerivedParameters pgen 256)
        password (.getKey cparams)]
    {:alg alg
     :password password
     :salt salt
     :iterations iterations}))

(defmethod derive-password :bcrypt+sha512
  [{:keys [alg password salt iterations]}]
  (let [salt (codecs/to-bytes (or salt (nonce/random-bytes 16)))
        iterations (or iterations (get +iterations+ alg))
        password (-> (hash/sha512 password)
                     (BCrypt/generate salt iterations))]
    {:alg alg
     :iterations iterations
     :salt salt
     :password password}))

(defmethod derive-password :bcrypt+blake2b-512
  [{:keys [alg password salt iterations] :as pwdparams}]
  (let [salt (codecs/to-bytes (or salt (nonce/random-bytes 16)))
        iterations (or iterations (get +iterations+ alg))
        password (-> (hash/blake2b-512 password)
                     (BCrypt/generate salt iterations))]
    {:alg alg
     :iterations iterations
     :salt salt
     :password password}))

(defmethod derive-password :bcrypt+sha384
  [{:keys [alg password salt iterations] :as pwdparams}]
  (let [salt (codecs/to-bytes (or salt (nonce/random-bytes 16)))
        iterations (or iterations (get +iterations+ alg))
        password (-> (hash/sha384 password)
                     (BCrypt/generate salt iterations))]
    {:alg alg
     :iterations iterations
     :salt salt
     :password password}))

(defmethod derive-password :scrypt
  [{:keys [alg password salt cpucost memcost parallelism] :as pwdparams}]
  (let [salt (codecs/to-bytes (or salt (nonce/random-bytes 12)))
        cpucost (or cpucost (get-in +iterations+ [:scrypt :cpucost]))
        memcost (or memcost (get-in +iterations+ [:scrypt :memcost]))
        parallelism (or parallelism 1)
        password (-> (bytes/concat salt password salt)
                     (codecs/bytes->hex)
                     (scrypt/encrypt cpucost memcost parallelism)
                     (codecs/str->bytes))]
    {:alg alg
     :cpucost cpucost
     :memcost memcost
     :parallelism parallelism
     :password password
     :salt salt}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Key Verification
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod check-password :bcrypt+sha512
  [params attempt]
  (let [pwdbytes (:password params)]
    (if (= (count pwdbytes) 24)
      (let [params' (assoc params :password attempt)
            candidate (derive-password params')]
        (bytes/equals? (:password params)
                       (:password candidate)))

      ;; Backward compatibility for password checking
      ;; for old algorithm
      (let [candidate (-> (bytes/concat attempt (:salt params))
                          (hash/sha512))]
        (buddy.impl.bcrypt.BCrypt/checkpw
         (codecs/bytes->hex candidate)
         (codecs/bytes->str (:password params)))))))

(defmethod check-password :scrypt
  [pwdparams attempt]
  (let [salt (:salt pwdparams)
        candidate (bytes/concat salt attempt salt)]
    (scrypt/verify (codecs/bytes->hex candidate)
                   (codecs/bytes->str (:password pwdparams)))))

(defn- derive-password-for-legacy-pbkdf2+sha256
  [{:keys [alg password salt saltsize iterations]}]
  (let [salt (codecs/to-bytes (or salt (nonce/random-bytes 12)))
        iterations (or iterations (get +iterations+ alg))
        pgen (doto (PKCS5S2ParametersGenerator. (SHA256Digest.))
               (.init password salt iterations))
        ^KeyParameter cparams (.generateDerivedParameters pgen 160)
        password (.getKey cparams)]
    {:alg alg
     :password password
     :salt salt
     :iterations iterations}))

(defmethod check-password :pbkdf2+sha256
  [params attempt]
  (let [pwdbytes (:password params)]
    (if (= (count pwdbytes) 20)
      ;; Backward compatibility with older passwords
      (let [params' (assoc params :password attempt)
            candidate (derive-password-for-legacy-pbkdf2+sha256 params')]
        (bytes/equals? (:password params)
                       (:password candidate)))
      (let [params' (assoc params :password attempt)
            candidate (derive-password params')]
        (bytes/equals? (:password params)
                       (:password candidate))))))

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
  (let [salt (codecs/bytes->hex salt)
        password (codecs/bytes->hex password)]
    (format "scrypt$%s$%s$%s$%s$%s" salt cpucost memcost parallelism password)))

(defmethod format-password :default
  [{:keys [alg password salt iterations]}]
  (let [algname (name alg)
        salt (codecs/bytes->hex salt)
        password (codecs/bytes->hex password)]
    (if (nil? iterations)
      (format "%s$%s$%s" algname salt password)
      (format "%s$%s$%s$%s" algname salt iterations password))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Key Parsing
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod parse-password :scrypt
  [encryptedpassword]
  (let [[alg salt cc mc pll password] (str/split encryptedpassword #"\$")
        alg (keyword alg)]
    (if (some nil? [salt cc mc pll password])
      (throw (ex-info "Malformed hash" {})))
    {:alg alg
     :salt (codecs/hex->bytes salt)
     :password (codecs/hex->bytes password)
     :cpucost (Integer/parseInt cc)
     :memcost (Integer/parseInt mc)
     :parallelism (Integer/parseInt pll)}))

(defmethod parse-password :default
  [encryptedpassword]
  (let [[alg salt iterations password] (str/split encryptedpassword #"\$")
        alg (keyword alg)]
    (if (some nil? [salt iterations password])
      (throw (ex-info "Malformed hash" {})))
    {:alg alg
     :salt (codecs/hex->bytes salt)
     :password (codecs/hex->bytes password)
     :iterations (Integer/parseInt iterations)}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Update Algorithm
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod must-update? :default
  [{:keys [alg iterations]}]
  (let [desired-iterations (get +iterations+ alg)]
    (and desired-iterations (> desired-iterations iterations))))

(defmethod must-update? :bcrypt+sha512
  [{:keys [password iterations alg]}]
  (or (not= (count password) 24)
      (let [desired-iterations (get +iterations+ alg)]
        (and desired-iterations (> desired-iterations iterations)))))

(defmethod must-update? :pbkdf2+sha256
  [{:keys [password iterations alg]}]
  (or (< (count password) 32)
      (let [desired-iterations (get +iterations+ alg)]
        (and desired-iterations (> desired-iterations iterations)))))

(defmethod must-update? :scrypt
  [{:keys [alg memcost cpucost]}]
  (let [desired-memcost (get-in +iterations+ [:scrypt :memcost])
        desired-cpucost (get-in +iterations+ [:scrypt :cpucost])]
    (and desired-cpucost
         desired-memcost
         (or (> desired-memcost memcost)
             (> desired-cpucost cpucost)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Public Api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn derive
  "Encrypts a raw string password."
  ([password] (derive password {}))
  ([password options]
   (-> (assoc options
              :alg (:alg options :bcrypt+sha512)
              :password (codecs/str->bytes password))
       (derive-password)
       (format-password))))

(defn check
  "Check if a unencrypted password matches
  with another encrypted password."
  ([attempt encrypted]
   (check attempt encrypted {}))
  ([attempt encrypted {:keys [limit setter prefered]}]
   (when (and attempt encrypted)
     (let [pwdparams (parse-password encrypted)]
       (if (and (set? limit) (not (contains? limit (:alg pwdparams))))
         false
         (let [attempt' (codecs/str->bytes attempt)
               result (check-password pwdparams attempt')]
           (when (and result (fn? setter) (must-update? pwdparams))
             (setter attempt))
           result))))))


(def encrypt
  "Backward compatibility alias for `derive`."
  derive)
