FROM maven:3.8-jdk-11-slim AS builder

WORKDIR /home/app

ADD pom.xml .
RUN mvn dependency:go-offline
ADD src/main src/main

RUN mvn package -Dmaven.test.skip=true

### Run Stage
FROM openjdk:11-jre-slim

COPY --from=builder /home/app/target/reconciler_lib /usr/local/lib/reconciler_lib
COPY --from=builder /home/app/target/reconciler-1.0.jar /usr/local/lib/reconciler-1.0.jar

WORKDIR /usr/local/lib/
ENTRYPOINT ["java", "-cp", "reconciler-1.0.jar:reconciler_lib/*", "edu.rit.se.nvip.ReconcilerMain"]