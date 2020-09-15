#!/bin/sh
mvn deploy:deploy-file -Dfile=target/buddy-hashers.jar -DpomFile=pom.xml -DrepositoryId=clojars -Durl=https://clojars.org/repo/
