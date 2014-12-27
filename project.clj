(defproject buddy/buddy-hashers "0.3.0-SNAPSHOT"
  :description "Security library for Clojure"
  :url "https://github.com/niwibe/buddy"
  :license {:name "BSD (2-Clause)"
            :url "http://opensource.org/licenses/BSD-2-Clause"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [buddy/buddy-core "0.3.0-SNAPSHOT"]
                 [clojurewerkz/scrypt "1.2.0"]]
  :source-paths ["src/clojure"]
  :java-source-paths ["src/java"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"]
  :test-paths ["test"]
  :profiles {:speclj {:dependencies [[speclj "3.1.0"]]
                      :test-paths ["spec"]
                      :plugins [[speclj "3.1.0"]]}})
