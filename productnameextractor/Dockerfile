FROM maven:3.8.7-openjdk-18-slim AS builder

WORKDIR /home/app

ADD pom.xml .
ADD crawler/pom.xml crawler/pom.xml
ADD exploitfinder/pom.xml exploitfinder/pom.xml
ADD patchfinder/pom.xml patchfinder/pom.xml
ADD productnameextractor/pom.xml productnameextractor/pom.xml
ADD reconciler/pom.xml reconciler/pom.xml

RUN mvn dependency:go-offline

ADD productnameextractor/src/main productnameextractor/src/main

RUN mvn package -Dmaven.test.skip=true --projects=productnameextractor

### Run Stage
FROM openjdk:11-jre-slim

# Mount data directory
VOLUME /usr/local/lib/nvip_data
ADD productnameextractor/nvip_data /usr/local/lib/nvip_data

COPY --from=builder /home/app/productnameextractor/target/productnameextractor_lib /usr/local/lib/productnameextractor_lib
COPY --from=builder /home/app/productnameextractor/target/productnameextractor-1.0.jar /usr/local/lib/productnameextractor-1.0.jar

WORKDIR /usr/local/lib/
ENTRYPOINT ["java", "-cp", "productnameextractor-1.0.jar:productnameextractor_lib/*", "ProductNameExtractorMain"]





