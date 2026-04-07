FROM eclipse-temurin:21-jdk-alpine AS builder

ARG GITHUB_TOKEN

WORKDIR /build

COPY mvnw .
COPY .mvn .mvn


COPY pom.xml .

RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'EOF'
<settings>
  <servers>
    <server>
      <id>github</id>
      <username>x-token</username>
      <password>${env.GITHUB_TOKEN}</password>
    </server>
  </servers>
</settings>
EOF

RUN chmod +x mvnw


RUN GITHUB_TOKEN=${GITHUB_TOKEN} ./mvnw dependency:go-offline -B

COPY src/ src/

RUN GITHUB_TOKEN=${GITHUB_TOKEN} ./mvnw package -DskipTests -B



#stage-2
FROM eclipse-temurin:21-jre-alpine AS runtime

RUN addgroup -S railway && adduser -S railway -G railway

WORKDIR /app

COPY --from=builder /build/target/railway-auth-service-*.jar app.jar

RUN chown railway:railway app.jar

RUN mkdir -p /app/logs && chown -R railway:railway /app/logs

USER railway

EXPOSE 8080

ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "app.jar"]

