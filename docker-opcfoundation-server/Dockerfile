FROM maven:latest

RUN apt-get update
WORKDIR /opt/workspace/

RUN git clone https://github.com/opcfoundation/ua-java.git
RUN cd ua-java/; git checkout 9006208b89ebdfabde76b6c4613301d75ac76c30

# make sure the server does not wait for user input
RUN sed -i -e "s/System.out.println(\"Press enter to shutdown\");//g" ./ua-java/examples/basic/src/main/java/org/opcfoundation/ua/examples/ServerExample1.java
RUN sed -i -e "s/System.in.read();/while (true) {Thread.sleep(10000);}/g" ./ua-java/examples/basic/src/main/java/org/opcfoundation/ua/examples/ServerExample1.java
RUN sed -i -e "s/myServer.getApplication().close();//g" ./ua-java/examples/basic/src/main/java/org/opcfoundation/ua/examples/ServerExample1.java

# skip tests and install library
RUN mvn $MAVEN_CLI_OPTS install -DskipTests -f ua-java/
# build examples
RUN mvn package -f ua-java/examples/basic/

ENTRYPOINT ["./ua-java/examples/basic/target/assemblies/bin/ServerExample1"]
