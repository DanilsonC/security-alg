# security-alg

A Clojure library designed to encrypt and decrypt text

## Usage

```clojure
;;You can change the key in this line
(def ^:const key "Tudo pelo kuduairo!")
```

Encrypting the text "Hello world!"
```clojure
(encrypt "Hello world!")
=> "C99tRo0K9GKmH9Rx7j7xWw=="
```
decrypting C99tRo0K9GKmH9Rx7j7xWw==
```clojure
(decrypt "C99tRo0K9GKmH9Rx7j7xWw==")
=> "Hello world!"
```


## License
This project is licensed under the MIT License

Copyright © Danilson de Carvalho