(defproject security-alg "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.10.3"]
                 [org.apache.commons/commons-lang3 "3.12.0"]
                 [commons-codec/commons-codec "1.15"]]
  :target-path "target/%s"
  :repl-options {:init-ns security-alg.core})
