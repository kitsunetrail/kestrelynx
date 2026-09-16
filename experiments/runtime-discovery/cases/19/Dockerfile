# case 19 (separate-archives condition): the library is a file of its own on the
# class path, which is the layout a scan report names directly. Build
# context is cases/images/19-jvm-jar (see cases/run.sh).
#
# The library version is pinned, and the case definition records why that
# version was chosen. Both stages are pinned by digest so the scan and the
# run describe the same bytes however the tags move.
FROM eclipse-temurin:17-jdk@sha256:36d9a76dc231587873b103c68a789b85d91b41d314dda69730d6bc43a777f2a9 AS build
ARG LOG4J_VERSION=2.14.1
ARG MAVEN_BASE=https://repo1.maven.org/maven2/org/apache/logging/log4j
WORKDIR /src
RUN mkdir -p /build \
    && curl -fsSL -o /build/log4j-core-${LOG4J_VERSION}.jar \
       "${MAVEN_BASE}/log4j-core/${LOG4J_VERSION}/log4j-core-${LOG4J_VERSION}.jar" \
    && curl -fsSL -o /build/log4j-api-${LOG4J_VERSION}.jar \
       "${MAVEN_BASE}/log4j-api/${LOG4J_VERSION}/log4j-api-${LOG4J_VERSION}.jar"
COPY App.java .
RUN javac -cp "/build/log4j-core-${LOG4J_VERSION}.jar:/build/log4j-api-${LOG4J_VERSION}.jar" -d /build/classes App.java \
    && jar --create --file /build/app.jar --main-class App -C /build/classes .

FROM eclipse-temurin:17-jre@sha256:c6f2875c05ea10f16398bdc5f73405c384991506f2f1ead8bcc6582ae8adea79
ARG LOG4J_VERSION=2.14.1
WORKDIR /app
COPY --from=build /build/app.jar /app/app.jar
COPY --from=build /build/log4j-core-${LOG4J_VERSION}.jar /app/log4j-core-${LOG4J_VERSION}.jar
COPY --from=build /build/log4j-api-${LOG4J_VERSION}.jar /app/log4j-api-${LOG4J_VERSION}.jar
ENV CASE_ID=19
ENV TARGET_FILE=/app/log4j-core-2.14.1.jar
ENV OPEN_CONDITION=startup_open
ENTRYPOINT ["sh", "-c", "exec java -cp /app/app.jar:/app/log4j-core-2.14.1.jar:/app/log4j-api-2.14.1.jar App"]
