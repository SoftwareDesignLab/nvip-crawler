FROM maven:3.8.7-openjdk-18-slim AS builder

WORKDIR /home/app

ADD pom.xml .
ADD crawler/pom.xml crawler/pom.xml
ADD exploitfinder/pom.xml exploitfinder/pom.xml
ADD patchfinder/pom.xml patchfinder/pom.xml
ADD productnameextractor/pom.xml productnameextractor/pom.xml
ADD reconciler/pom.xml reconciler/pom.xml

RUN mvn dependency:go-offline

ADD patchfinder/src/main patchfinder/src/main

RUN mvn package -Dmaven.test.skip=true --projects=patchfinder

### Patchfinder Run Stage
FROM openjdk:11-jre-slim AS patchfinder

# Mount data directory
VOLUME /usr/local/lib/nvip_data
ADD patchfinder/src/main/resources /usr/local/lib/nvip_data

COPY --from=builder /home/app/patchfinder/target/patchfinder_lib /usr/local/lib/patchfinder_lib
COPY --from=builder /home/app/patchfinder/target/patchfinder-1.0.jar /usr/local/lib/patchfinder-1.0.jar

WORKDIR /usr/local/lib/
ENTRYPOINT ["java", "-cp", "patchfinder-1.0.jar:patchfinder_lib/*", "PatchFixMain"]


