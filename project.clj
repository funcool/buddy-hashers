(defproject buddy/buddy-hashers "0.4.1"
  :description "Security library for Clojure"
  :url "https://github.com/funcool/buddy-hashers"
  :license {:name "BSD (2-Clause)"
            :url "http://opensource.org/licenses/BSD-2-Clause"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [buddy/buddy-core "0.4.2"]
                 [clojurewerkz/scrypt "1.2.0"]]
  :source-paths ["src/clojure"]
  :java-source-paths ["src/java"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"]
  :test-paths ["test"])
