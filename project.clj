(defproject buddy/buddy-hashers "1.7.0"
  :description "A collection of secure password hashers for Clojure"
  :url "https://github.com/funcool/buddy-hashers"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.10.1" :scope "provided"]
                 [buddy/buddy-core "1.9.0"]
                 [clojurewerkz/scrypt "1.2.0"]]
  :jar-name "buddy-hashers.jar"
  :source-paths ["src/clj"]
  :java-source-paths ["src/java"]
  :javac-options ["-target" "1.8" "-source" "1.8" "-Xlint:-options"]
  :test-paths ["test"])
