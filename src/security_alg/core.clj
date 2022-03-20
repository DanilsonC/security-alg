(ns security-alg.core
  (:import (javax.crypto Cipher)
           (javax.crypto.spec IvParameterSpec SecretKeySpec)
           (java.security MessageDigest)
           (org.apache.commons.codec.binary Base64)
           (org.apache.commons.lang3 StringUtils)))

(def ^:const key "Tudo pelo kuduairo!")
(def ^:const dataCypher "AES/CBC/PKCS5Padding")
(def ^:const keyCypher "AES")
(def ^:const digestAlgo "MD5")

(def ecipher)
(def dcipher)

(def salt (byte-array [(unchecked-byte 0x83) (unchecked-byte 0x0f) (unchecked-byte 0x9d) (unchecked-byte 0xa9)
                       (unchecked-byte 0xdc) (unchecked-byte 0x03) (unchecked-byte 0x03) (unchecked-byte 0x83)
                       (unchecked-byte 0xe0) (unchecked-byte 0xb6) (unchecked-byte 0xf1) (unchecked-byte 0x53)
                       (unchecked-byte 0x79) (unchecked-byte 0x59) (unchecked-byte 0x80) (unchecked-byte 0xcb)]))

(defn md5sum [^bytes buffer]
  (let [^MessageDigest digest (MessageDigest/getInstance digestAlgo)]
    (.update digest buffer)
    (.digest digest)))

(defn security [passPhrase]
  (let [^IvParameterSpec ivSpec (IvParameterSpec. salt)]
    (try
      (let [md5sum_ (md5sum (.getBytes passPhrase))
           ^SecretKeySpec key (SecretKeySpec. md5sum_, keyCypher)]
        (def ecipher (Cipher/getInstance dataCypher))
        (def dcipher (Cipher/getInstance dataCypher))
        (.init ecipher (Cipher/ENCRYPT_MODE) key ivSpec)
        (.init dcipher (Cipher/DECRYPT_MODE) key ivSpec))
      (catch Exception e
        (throw (IllegalStateException. "the cypher failed to intialize due to bad configuration" e))))))

(defn encrypt [plaintext]
  (security key)
  (if (StringUtils/isBlank plaintext)
    (throw (IllegalStateException. "plaintext is undefined")))
  (-> (.doFinal ecipher (.getBytes plaintext))
      (Base64/encodeBase64)
      (String.)))

(defn decrypt [cyphertext]
  (security key)
  (if (StringUtils/isBlank cyphertext)
    (throw (IllegalStateException. "cyphertext is undefined")))
  (try
    (->> (Base64/decodeBase64 (.getBytes cyphertext))
         (.doFinal dcipher)
         (String.))
    (catch IllegalStateException e
      (assert false))))
