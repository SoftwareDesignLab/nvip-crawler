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
ADD nvip_data /usr/local/lib/nvip_data

COPY --from=builder /home/app/target/productnameextractor_lib /usr/local/lib/productnameextractor_lib
COPY --from=builder /home/app/target/productnameextractor-1.0.jar /usr/local/lib/productnameextractor-1.0.jar

WORKDIR /usr/local/lib/
ENTRYPOINT ["java", "-cp", "productnameextractor-1.0.jar:productnameextractor_lib/*", "edu.rit.se.nvip.ProductNameExtractorMain"]





