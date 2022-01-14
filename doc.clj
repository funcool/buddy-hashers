(require '[codox.main :as codox])

(codox/generate-docs
 {:output-path "doc/dist/latest"
  :metadata {:doc/format :markdown}
  :language :clojure
  :name "buddy/buddy-hashers"
  :themes [:rdash]
  :source-paths ["src/clj"]
  :namespaces [#"^buddy\."]
  :source-uri "https://github.com/funcool/buddy-hashers/blob/master/{filepath}#L{line}"})
