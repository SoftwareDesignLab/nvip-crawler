FROM maven:3.8-jdk-11-slim AS builder

WORKDIR /home/app

ADD pom.xml .
RUN mvn dependency:go-offline
ADD src/main src/main

RUN mvn package -Dmaven.test.skip=true

### Run Stage
FROM openjdk:11-jre-slim

# Mount data directory
VOLUME /usr/local/lib/nvip_data
ADD src/main/resources /usr/local/lib/nvip_data

COPY --from=builder /home/app/target/patchfinder_lib /usr/local/lib/patchfinder_lib
COPY --from=builder /home/app/target/patchfinder-1.0.jar /usr/local/lib/patchfinder-1.0.jar

WORKDIR /usr/local/lib/
ENTRYPOINT ["java", "-cp", "patchfinder-1.0.jar:patchfinder_lib/*", "PatchFinderMain"]





