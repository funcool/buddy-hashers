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
           java.security.Security
           buddy.impl.bcrypt.BCrypt))

(when (nil? (Security/getProvider "BC"))
  (Security/addProvider (org.bouncycastle.jce.provider.BouncyCastleProvider.)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Constants
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def ^:dynamic *default-iterations*
  {:pbkdf2+sha1 100000
   :pbkdf2+sha256 100000
   :pbkdf2+sha3_256 5000
   :pbkdf2+sha3-256 5000
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
  (let [salt (->byte-array (or salt (nonce/random-bytes 12)))
        alg (keyword (str "pbkdf2+" (name digest)))
        iterations (or iterations (get *default-iterations* alg))
        digest (hash/resolve-digest-engine digest)
        dsize (* 8 (.getDigestSize digest))
        pgen (doto (PKCS5S2ParametersGenerator. digest)
               (.init password salt iterations))
        password (.getKey (.generateDerivedParameters pgen dsize))]
    {:alg alg
     :password password
     :salt salt
     :iterations iterations}))

(defmethod derive-password :pbkdf2+sha1
  [options]
  (derive-password (assoc options :alg :pbkdf2 :digest :sha1)))

;; NOTE: this is a special case for the previous impl that
;; uses weaker configuration that it should be. This weaker
;; impl implies the same security as :pbkdf2+sha1 with stronger
;; hasher implementation truncated to 160 bytes. It menans that
;; it at least secure as :pbkdf2+sha1 that is considered secure.

(defmethod derive-password :pbkdf2+sha256b
  [{:keys [alg password salt iterations] :as pwdparams}]
  (let [salt (->byte-array (or salt (nonce/random-bytes 12)))
        iterations (or iterations (get *default-iterations* alg))
        pgen (doto (PKCS5S2ParametersGenerator. (SHA256Digest.))
               (.init password salt iterations))
        password (.getKey (.generateDerivedParameters pgen 160))]
    {:alg alg
     :password password
     :salt salt
     :iterations iterations}))

(defmethod derive-password :pbkdf2+sha256
  [options]
  (derive-password (assoc options :alg :pbkdf2 :digest :sha256)))

(defmethod derive-password :pbkdf2+sha3-256
  [options]
  (derive-password (assoc options :alg :pbkdf2 :digest :sha3-256)))

;; WARNING: this is an alias for :pbkdf2+sha3-256 and should be consdered
;; deprecated. It will be removed in the next version.

(defmethod derive-password :pbkdf2+sha3_256
  [{:keys [alg password salt iterations] :as pwdparams}]
  (let [salt (->byte-array (or salt (nonce/random-bytes 12)))
        iterations (or iterations (get *default-iterations* alg))
        pgen (doto (PKCS5S2ParametersGenerator. (SHA3Digest. 256))
               (.init password salt iterations))
        password (.getKey (.generateDerivedParameters pgen 256))]
    {:alg alg
     :password password
     :salt salt
     :iterations iterations}))

;; NOTE: this impl hash the problem of the sha512 truncation to the 256 bits.
;; It is not very big problem in terms of security or collision because
;; sha256 is still secure and colision resistant. But is now deprecated
;; bacause it does not works as expected.

(defmethod derive-password :bcrypt+sha512
  [{:keys [alg password salt iterations] :as pwdparams}]
  (let [salt (->byte-array (or salt (nonce/random-bytes 12)))
        iterations (or iterations (get *default-iterations* alg))
        iv (BCrypt/gensalt iterations)
        pwd (-> password
                (bytes/concat salt)
                (hash/sha512)
                (bytes->hex)
                (BCrypt/hashpw iv)
                (str->bytes))]
    {:alg alg
     :iterations iterations
     :salt salt
     :password pwd}))

(defmethod derive-password :scrypt
  [{:keys [alg password salt cpucost memcost parallelism] :as pwdparams}]
  (let [salt (->byte-array (or salt (nonce/random-bytes 12)))
        cpucost (or cpucost (get-in *default-iterations* [:scrypt :cpucost]))
        memcost (or memcost (get-in *default-iterations* [:scrypt :memcost]))
        parallelism (or parallelism 1)
        password (-> (bytes/concat salt password salt)
                     (bytes->hex)
                     (scrypt/encrypt cpucost memcost parallelism)
                     (str->bytes))]
    {:alg alg
     :cpucost cpucost
     :memcost memcost
     :parallelism parallelism
     :password password
     :salt salt}))

(defmethod derive-password :sha256
  [{:keys [alg password salt] :as pwdparams}]
  (let [salt (->byte-array (or salt (nonce/random-bytes 12)))
        password (-> (bytes/concat password salt)
                     (hash/sha256))]
    {:alg :sha256
     :password password
     :salt salt}))

(defmethod derive-password :md5
  [{:keys [alg password salt] :as pwdparams}]
  (let [salt (->byte-array (or salt (nonce/random-bytes 12)))
        password (-> (bytes/concat password salt)
                     (hash/md5))]
    {:alg :md5
     :password password
     :salt salt}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Key Verification
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; DEPRECATED: see note on derive-password

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
  [{:keys [alg password salt iterations]}]
  (let [algname (name alg)
        salt (bytes->hex salt)
        password (bytes->hex password)]
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
    {:alg alg
     :salt (hex->bytes salt)
     :password (hex->bytes password)
     :cpucost (Integer/parseInt cc)
     :memcost (Integer/parseInt mc)
     :parallelism (Integer/parseInt pll)}))

(defmethod parse-password :sha256
  [encryptedpassword]
  (let [[alg salt password] (str/split encryptedpassword #"\$")
        alg (keyword alg)]
    {:alg alg
     :salt (hex->bytes salt)
     :password (hex->bytes password)}))

(defmethod parse-password :md5
  [encryptedpassword]
  (let [[alg salt password] (str/split encryptedpassword #"\$")
        alg (keyword alg)]
    {:alg alg
     :salt (hex->bytes salt)
     :password (hex->bytes password)}))

(defmethod parse-password :default
  [encryptedpassword]
  (let [[alg salt iterations password] (str/split encryptedpassword #"\$")
        alg (keyword alg)]
    {:alg alg
     :salt (hex->bytes salt)
     :password (hex->bytes password)
     :iterations (Integer/parseInt iterations)}))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Update Algorithm
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod must-update? :default
  [{:keys [alg iterations]}]
  (let [desired-iterations (get *default-iterations* alg)]
    (and desired-iterations (> desired-iterations iterations))))

(defmethod must-update? :bcrypt+sha512
  [{:keys [alg iterations]}]
  true)

(defmethod must-update? :scrypt
  [{:keys [alg memcost cpucost]}]
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
   (let [alg (or (:algorithm options nil)
                 (:alg options)
                 :bcrypt+sha512)
         pwdparams (assoc options
                          :alg alg
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
       (if (and (set? limit) (not (contains? limit (:alg pwdparams))))
         false
         (let [attempt' (str->bytes attempt)
               result (check-password pwdparams attempt')]
           (when (and result (fn? setter) (must-update? pwdparams))
             (setter attempt))
           result))))))
