(ns build
  (:refer-clojure :exclude [compile])
  (:require
   [clojure.tools.build.api :as b]))

(def lib 'buddy/buddy-hashers)
(def version (format "2.0.%s" (b/git-count-revs nil)))
(def class-dir "target/classes")
(def dist-dir "target/dist")
(def basis (b/create-basis {:project "deps.edn"}))
(def jar-file (format "target/%s-%s.jar" (name lib) version))

(defn clean [_]
  (b/delete {:path "target"}))

(defn jar [_]
  (b/write-pom
   {:class-dir dist-dir
    :lib lib
    :version version
    :basis basis
    :src-dirs ["src/clj"]})

  (b/copy-dir
   {:src-dirs ["src/clj" "target/classes"]
    :target-dir dist-dir})

  (b/jar
   {:class-dir dist-dir
    :jar-file jar-file}))

(defn compile [_]
  (b/javac
   {:src-dirs ["src/java"]
    :class-dir class-dir
    :basis basis
    :javac-opts ["-source" "1.8" "-target" "1.8"]}))

(defn clojars [_]
  (b/process
   {:command-args ["mvn"
                   "deploy:deploy-file"
                   (str "-Dfile=" jar-file)
                   "-DpomFile=target/dist/META-INF/maven/buddy/buddy-hashers/pom.xml"
                   "-DrepositoryId=clojars"
                   "-Durl=https://clojars.org/repo/"]}))
