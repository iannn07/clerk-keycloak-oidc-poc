FROM maven:3.9-eclipse-temurin-21 AS plugin
WORKDIR /src
COPY clerk-authenticator/pom.xml ./
COPY clerk-authenticator/src ./src
RUN mvn -q -B package

FROM quay.io/keycloak/keycloak:26.6.4
COPY --from=plugin /src/target/clerk-authenticator.jar /opt/keycloak/providers/
