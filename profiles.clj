{:dev
 {:aliases {"test-all" ["with-profile" "dev:dev,1.9:dev,1.8:dev,1.7:dev,1.6:dev,1.5" "test"]}
  :plugins [[lein-codox "0.10.7"]
            [lein-ancient "0.6.15"]]
  :dependencies [[org.clojure/tools.reader "1.1.0"]
                 [codox-theme-rdash "0.1.2"]]
  :codox {:project {:name "buddy-hashers"}
          :metadata {:doc/format :markdown}
          :output-path "doc/dist/latest/"
          :doc-paths ["doc/"]
          :themes [:rdash]
          :source-paths ["src/clj"]
          :source-uri "https://github.com/funcool/buddy-hashers/blob/master/{filepath}#L{line}"
          :namespaces [#"^buddy\."]}}

 :1.6 {:dependencies [[org.clojure/clojure "1.6.0"]]}
 :1.5 {:dependencies [[org.clojure/clojure "1.5.1"]]}
 :1.7 {:dependencies [[org.clojure/clojure "1.7.0"]]}
 :1.8 {:dependencies [[org.clojure/clojure "1.8.0"]]}
 :1.9 {:dependencies [[org.clojure/clojure "1.9.0"]]}}

