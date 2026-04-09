FROM eclipse-temurin:21-jdk-alpine AS builder

WORKDIR /app

COPY .mvn/ .mvn/
COPY mvnw pom.xml ./

ARG GITHUB_ACTOR
ARG GITHUB_TOKEN

RUN ./mvnw dependency:go-offline \
    -s .mvn/settings.xml \
    -Dgithub.actor=${GITHUB_ACTOR} \
    -Dgithub.token=${GITHUB_TOKEN} \
    --no-transfer-progress


COPY src ./src

RUN ./mvnw package -DskipTests \
    -s .mvn/settings.xml \
    -Dgithub.actor=${GITHUB_ACTOR} \
    -Dgithub.token=${GITHUB_TOKEN} \
    --no-transfer-progress



FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

RUN addgroup -S railway && adduser -S railway -G railway

COPY --from=builder /app/target/railway-auth-service-*.jar app.jar

RUN chown railway:railway app.jar

USER railway

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]

