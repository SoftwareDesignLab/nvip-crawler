FROM maven:3.8.7-openjdk-18-slim AS builder

WORKDIR /home/app

ADD pom.xml .
ADD crawler/pom.xml crawler/pom.xml
ADD exploitfinder/pom.xml exploitfinder/pom.xml
ADD patchfinder/pom.xml patchfinder/pom.xml
ADD productnameextractor/pom.xml productnameextractor/pom.xml
ADD reconciler/pom.xml reconciler/pom.xml

RUN mvn dependency:go-offline

ADD crawler/src/main crawler/src/main

RUN mvn package -Dmaven.test.skip=true --projects=crawler

### Crawler Run Stage
FROM eclipse-temurin:17-jre AS crawler

RUN apt-get update \
    && apt-get install -y libglib2.0-0 libnss3 libxcb1

RUN apt-get install -y wget
RUN wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
RUN apt-get install -y ./google-chrome-stable_current_amd64.deb

VOLUME /usr/local/lib/resources
COPY crawler/resources /usr/local/lib/resources

VOLUME /usr/local/lib/output
COPY crawler/output /usr/local/lib/output

COPY --from=builder /home/app/crawler/target/nvip_lib /usr/local/lib/nvip_lib
COPY --from=builder /home/app/crawler/target/crawler-2.0.jar /usr/local/lib/crawler-2.0.jar

WORKDIR /usr/local/lib/
ENTRYPOINT ["java", "-cp", "crawler-2.0.jar:nvip_lib/*", "edu.rit.se.nvip.CrawlerMain"]
