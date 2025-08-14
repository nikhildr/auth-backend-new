FROM openjdk:17-jdk-alpine

WORKDIR /app

COPY target/auth-service-1.0.0.jar app.jar

EXPOSE 8080

CMD [ "java","-jar","app.jar" ]