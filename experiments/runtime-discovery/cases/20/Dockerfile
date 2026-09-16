# case 20 (nested-archives condition): the library archives are packed inside the
# program's own archive, so the only file the system ever opens is the
# outer one. Build context is cases/images/19-jvm-jar (see cases/run.sh).
#
# This condition exists to measure what a scan report says about an archive
# inside an archive, and what an observation of the outer file can honestly
# support: that the outer file was read, and not that any particular inner
# archive was loaded.
FROM eclipse-temurin:17-jdk@sha256:36d9a76dc231587873b103c68a789b85d91b41d314dda69730d6bc43a777f2a9 AS build
ARG LOG4J_VERSION=2.14.1
ARG MAVEN_BASE=https://repo1.maven.org/maven2/org/apache/logging/log4j
WORKDIR /src
RUN mkdir -p /build/lib \
    && curl -fsSL -o /build/lib/log4j-core-${LOG4J_VERSION}.jar \
       "${MAVEN_BASE}/log4j-core/${LOG4J_VERSION}/log4j-core-${LOG4J_VERSION}.jar" \
    && curl -fsSL -o /build/lib/log4j-api-${LOG4J_VERSION}.jar \
       "${MAVEN_BASE}/log4j-api/${LOG4J_VERSION}/log4j-api-${LOG4J_VERSION}.jar"
COPY App.java .
# The program's own classes are compiled against the libraries, the
# libraries' classes are unpacked alongside them so the runtime can load
# them from the single archive, and the library archives themselves are
# packed in as well so a scan report sees an archive inside an archive.
RUN mkdir -p /build/classes /build/unpacked \
    && javac -cp "/build/lib/log4j-core-${LOG4J_VERSION}.jar:/build/lib/log4j-api-${LOG4J_VERSION}.jar" -d /build/classes App.java \
    && (cd /build/unpacked && jar --extract --file /build/lib/log4j-api-${LOG4J_VERSION}.jar && jar --extract --file /build/lib/log4j-core-${LOG4J_VERSION}.jar && rm -rf META-INF/*.SF META-INF/*.DSA META-INF/*.RSA) \
    && cp -r /build/unpacked/. /build/classes/ \
    && mkdir -p /build/classes/BOOT-INF/lib \
    && cp /build/lib/*.jar /build/classes/BOOT-INF/lib/ \
    && jar --create --file /build/fat.jar --main-class App -C /build/classes .

FROM eclipse-temurin:17-jre@sha256:c6f2875c05ea10f16398bdc5f73405c384991506f2f1ead8bcc6582ae8adea79
WORKDIR /app
COPY --from=build /build/fat.jar /app/fat.jar
ENV CASE_ID=20
# The file the load really reads is the outer archive: the inner ones are
# entries in it, never files the system opens.
ENV TARGET_FILE=/app/fat.jar
ENV OPEN_CONDITION=startup_open
ENV NESTED_ENTRY=BOOT-INF/lib/log4j-core-2.14.1.jar
ENV NESTED_NOTE="the library is an entry inside this archive, so the observation covers the outer file and does not show the inner archive being loaded on its own"
ENTRYPOINT ["sh", "-c", "exec java -jar /app/fat.jar"]
