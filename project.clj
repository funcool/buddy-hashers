(defproject buddy/buddy-hashers "1.5.0"
  :description "A collection of secure password hashers for Clojure"
  :url "https://github.com/funcool/buddy-hashers"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.10.1" :scope "provided"]
                 [buddy/buddy-core "1.7.1"]
                 [clojurewerkz/scrypt "1.2.0"]]
  :source-paths ["src"]
  :javac-options ["-target" "1.8" "-source" "1.8" "-Xlint:-options"]
  :test-paths ["test"])
