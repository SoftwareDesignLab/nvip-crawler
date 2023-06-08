FROM maven:3.8-jdk-11-slim AS builder

WORKDIR /home/app

ADD pom.xml .
RUN mvn dependency:go-offline
ADD src/main src/main

RUN mvn package -Dmaven.test.skip=true

### Run Stage
FROM openjdk:11-jre-slim

RUN apt-get update \
    && apt-get install -y libglib2.0-0 libnss3 libxcb1

RUN apt-get install -y wget
RUN wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
RUN apt-get install -y ./google-chrome-stable_current_amd64.deb

VOLUME /usr/local/lib/resources
ADD resources /usr/local/lib/resources

VOLUME /usr/local/lib/output
ADD output /usr/local/lib/output

COPY --from=builder /home/app/target/nvip_lib /usr/local/lib/nvip_lib
COPY --from=builder /home/app/target/nvip-1.0.jar /usr/local/lib/nvip-1.0.jar

WORKDIR /usr/local/lib/
ENTRYPOINT ["java", "-cp", "nvip-1.0.jar:nvip_lib/*", "edu.rit.se.nvip.CrawlerMain"]
