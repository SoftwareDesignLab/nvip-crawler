FROM maven:3.8.7-openjdk-18-slim AS builder

WORKDIR /home/app

ADD pom.xml .
ADD db/pom.xml db/pom.xml
ADD crawler/pom.xml crawler/pom.xml
ADD exploitfinder/pom.xml exploitfinder/pom.xml
ADD patchfinder/pom.xml patchfinder/pom.xml
ADD productnameextractor/pom.xml productnameextractor/pom.xml
ADD reconciler/pom.xml reconciler/pom.xml

ADD db/src/main db/src/main
RUN mvn install -Dmaven.test.skip=true --projects=db

RUN mvn dependency:go-offline --projects=db,reconciler

ADD reconciler/src/main reconciler/src/main

RUN mvn package -Dmaven.test.skip=true --projects=db,reconciler

### Reconciler Run Stage
FROM openjdk:11-jre-slim

VOLUME /usr/local/lib/nvip_data
ADD reconciler/nvip_data /usr/local/lib/nvip_data

VOLUME /usr/local/lib/characterization
ADD reconciler/characterization /usr/local/lib/characterization

COPY --from=builder /home/app/reconciler/target/reconciler_lib /usr/local/lib/reconciler_lib
COPY --from=builder /home/app/reconciler/target/reconciler-1.0.jar /usr/local/lib/reconciler-1.0.jar

WORKDIR /usr/local/lib
ENTRYPOINT ["java", "-cp", "reconciler-1.0.jar:reconciler_lib/*", "edu.rit.se.nvip.ReconcilerMain"]
