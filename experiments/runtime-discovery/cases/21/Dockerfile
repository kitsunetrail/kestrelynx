# case 21 (late-open condition): the library archive is present but not on the
# class path, so the runtime does not open it at startup and the load
# itself is what opens the file. Build context is
# cases/images/19-jvm-jar (see cases/run.sh).
#
# It is the companion to the separate-archives condition, where the runtime
# opens the archive before the program runs and holds it open — there, a
# load reads from a descriptor that already exists and opens nothing. The
# same load therefore produces a different observation in the two, and
# which one applies has to be recorded rather than assumed.
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
ENV CASE_ID=21
ENV TARGET_FILE=/app/log4j-core-2.14.1.jar
ENV OPEN_CONDITION=load_open
ENV LOADER_JARS=/app/log4j-core-2.14.1.jar:/app/log4j-api-2.14.1.jar
# Only the program's own archive is on the class path: the library is
# reached through a loader built on the firing signal, so the file is
# opened by the load.
ENTRYPOINT ["sh", "-c", "exec java -cp /app/app.jar App"]
