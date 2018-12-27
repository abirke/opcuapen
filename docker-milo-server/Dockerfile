FROM debian:latest

# use a performant apt mirror
RUN sed -i 's/de.archive.ubuntu.com/ftp.halifax.rwth-aachen.de/g' /etc/apt/sources.list
RUN sed -i 's/deb.debian.org/ftp.halifax.rwth-aachen.de/g' /etc/apt/sources.list

# install apt dependencies
RUN apt-get update
RUN apt-get install -y openjdk-8-jdk maven git

WORKDIR /opt/workspace/

RUN git clone --branch release/0.2.4 https://github.com/eclipse/milo.git

# skip certificate validation
RUN sed -i 's/import org.eclipse.milo.opcua.stack.core.application.DirectoryCertificateValidator;/import org.eclipse.milo.opcua.stack.core.application.InsecureCertificateValidator;/g' milo/milo-examples/server-examples/src/main/java/org/eclipse/milo/examples/server/ExampleServer.java
RUN sed -i 's/DirectoryCertificateValidator certificateValidator = new DirectoryCertificateValidator(pkiDir);/InsecureCertificateValidator certificateValidator = new InsecureCertificateValidator();/g' milo/milo-examples/server-examples/src/main/java/org/eclipse/milo/examples/server/ExampleServer.java

RUN mvn -DskipTests clean install -f milo/pom.xml

# start the server example
ENTRYPOINT ["java", "-jar", "milo/milo-examples/server-examples/target/server-examples-0.2.5-SNAPSHOT.jar"]
