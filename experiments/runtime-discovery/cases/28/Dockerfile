# case 28 (coverage-validation case): an HTTP application whose class
# path and lazily-loaded archives span 12 independent jars across three
# groups. Build context is cases/images/28-java-app (see cases/run.sh).
#
# Each group's jars are placed under a different directory so the runtime
# stage's own -cp and this program's own late class loaders decide which
# ones are ever opened, rather than a build-time distinction that the
# running container does not itself reproduce: /app/libs is on the launch
# class path, /app/lazy is opened only by a class loader App builds after
# firing, and /app/unused is never referenced by anything.
FROM eclipse-temurin:17-jdk@sha256:bc033b57e11b773c3043babfd664e7a5ef110805548b921cbfc3e8c67a0725d6 AS build
WORKDIR /build
RUN mkdir -p /build/libs \
    && curl -fsSL -o /build/libs/commons-lang3-3.14.0.jar https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar \
    && curl -fsSL -o /build/libs/commons-text-1.11.0.jar https://repo1.maven.org/maven2/org/apache/commons/commons-text/1.11.0/commons-text-1.11.0.jar \
    && curl -fsSL -o /build/libs/gson-2.10.1.jar https://repo1.maven.org/maven2/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar \
    && curl -fsSL -o /build/libs/slf4j-api-2.0.13.jar https://repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.jar \
    && curl -fsSL -o /build/libs/slf4j-simple-2.0.13.jar https://repo1.maven.org/maven2/org/slf4j/slf4j-simple/2.0.13/slf4j-simple-2.0.13.jar \
    && curl -fsSL -o /build/libs/jackson-databind-2.17.1.jar https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.17.1/jackson-databind-2.17.1.jar \
    && curl -fsSL -o /build/libs/jackson-core-2.17.1.jar https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-core/2.17.1/jackson-core-2.17.1.jar \
    && curl -fsSL -o /build/libs/jackson-annotations-2.17.1.jar https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-annotations/2.17.1/jackson-annotations-2.17.1.jar \
    && curl -fsSL -o /build/libs/commons-io-2.15.1.jar https://repo1.maven.org/maven2/commons-io/commons-io/2.15.1/commons-io-2.15.1.jar \
    && curl -fsSL -o /build/libs/guava-33.2.1-jre.jar https://repo1.maven.org/maven2/com/google/guava/guava/33.2.1-jre/guava-33.2.1-jre.jar \
    && curl -fsSL -o /build/libs/commons-codec-1.16.1.jar https://repo1.maven.org/maven2/commons-codec/commons-codec/1.16.1/commons-codec-1.16.1.jar \
    && curl -fsSL -o /build/libs/commons-collections4-4.4.jar https://repo1.maven.org/maven2/org/apache/commons/commons-collections4/4.4/commons-collections4-4.4.jar
COPY App.java LazyJacksonUser.java LazyCommonsIoUser.java /build/
RUN mkdir -p /build/classes/app /build/classes/lazy \
    && javac -cp "/build/libs/commons-lang3-3.14.0.jar:/build/libs/commons-text-1.11.0.jar:/build/libs/gson-2.10.1.jar:/build/libs/slf4j-api-2.0.13.jar" \
         -d /build/classes/app /build/App.java \
    && javac -cp "/build/libs/jackson-databind-2.17.1.jar:/build/libs/jackson-core-2.17.1.jar:/build/libs/jackson-annotations-2.17.1.jar" \
         -d /build/classes/lazy /build/LazyJacksonUser.java \
    && javac -cp "/build/libs/commons-io-2.15.1.jar" \
         -d /build/classes/lazy /build/LazyCommonsIoUser.java \
    && find /build/classes -exec touch -t 202601010000 {} + \
    && jar --create --file /build/app.jar --main-class App -C /build/classes/app . \
    && jar --create --file /build/lazy-classes.jar -C /build/classes/lazy .

FROM eclipse-temurin:17-jre@sha256:bd25c61779663bc2df8ced059f1cc114fafc073afe16125c13fcc3a37fecd845
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl git openssl strace \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /build/app.jar /app/app.jar
COPY --from=build /build/libs/commons-lang3-3.14.0.jar /app/libs/commons-lang3-3.14.0.jar
COPY --from=build /build/libs/commons-text-1.11.0.jar /app/libs/commons-text-1.11.0.jar
COPY --from=build /build/libs/gson-2.10.1.jar /app/libs/gson-2.10.1.jar
COPY --from=build /build/libs/slf4j-api-2.0.13.jar /app/libs/slf4j-api-2.0.13.jar
COPY --from=build /build/libs/slf4j-simple-2.0.13.jar /app/libs/slf4j-simple-2.0.13.jar
COPY --from=build /build/lazy-classes.jar /app/lazy/lazy-classes.jar
COPY --from=build /build/libs/jackson-databind-2.17.1.jar /app/lazy/jackson-databind-2.17.1.jar
COPY --from=build /build/libs/jackson-core-2.17.1.jar /app/lazy/jackson-core-2.17.1.jar
COPY --from=build /build/libs/jackson-annotations-2.17.1.jar /app/lazy/jackson-annotations-2.17.1.jar
COPY --from=build /build/libs/commons-io-2.15.1.jar /app/lazy/commons-io-2.15.1.jar
COPY --from=build /build/libs/guava-33.2.1-jre.jar /app/unused/guava-33.2.1-jre.jar
COPY --from=build /build/libs/commons-codec-1.16.1.jar /app/unused/commons-codec-1.16.1.jar
COPY --from=build /build/libs/commons-collections4-4.4.jar /app/unused/commons-collections4-4.4.jar
COPY os-ops.sh /os-ops.sh
COPY dump-runtime-modules.sh /dump-runtime-modules.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /os-ops.sh /dump-runtime-modules.sh /entrypoint.sh \
    && mkdir -p /opt/fixture-repo \
    && cd /opt/fixture-repo \
    && git init -q \
    && git config user.email fixture@example.invalid \
    && git config user.name fixture \
    && echo "case28 fixture" > README.md \
    && git add README.md \
    && GIT_AUTHOR_DATE="2026-01-01T00:00:00Z" GIT_COMMITTER_DATE="2026-01-01T00:00:00Z" \
       git commit -q -m "fixture" \
    && printf 'kestrelynx-coverage-fixture-digest-input\n%.0s' $(seq 1 128) > digest-input.txt \
    && git add digest-input.txt \
    && GIT_AUTHOR_DATE="2026-01-01T00:00:01Z" GIT_COMMITTER_DATE="2026-01-01T00:00:01Z" \
       git commit -q -m "digest input"
ENV CASE_ID=28
ENV HEALTH_URL=http://127.0.0.1:8080/health
ENTRYPOINT ["/entrypoint.sh"]
