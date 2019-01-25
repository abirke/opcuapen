FROM maven:latest

RUN apt-get update
WORKDIR /opt/workspace/

RUN git clone https://github.com/opcfoundation/ua-java.git
WORKDIR /opt/workspace/ua-java/
RUN git checkout 9006208b89ebdfabde76b6c4613301d75ac76c30

# use Bouncy Castle 1.60 instead of 1.54 for server example
ADD bouncycastle-1-60.diff .
RUN git apply --ignore-space-change --ignore-whitespace bouncycastle-1-60.diff

# make sure the server does not wait for user input
RUN sed -i -e "s/System.out.println(\"Press enter to shutdown\");//g" examples/basic/src/main/java/org/opcfoundation/ua/examples/ServerExample1.java
RUN sed -i -e "s/System.in.read();/while (true) {Thread.sleep(10000);}/g" examples/basic/src/main/java/org/opcfoundation/ua/examples/ServerExample1.java
RUN sed -i -e "s/myServer.getApplication().close();//g" examples/basic/src/main/java/org/opcfoundation/ua/examples/ServerExample1.java

ARG MAVEN_CLI_OPTS=-DskipTests
# skip tests and install ua-java stack
RUN mvn $MAVEN_CLI_OPTS install
# build examples
RUN mvn $MAVEN_CLI_OPTS package -f examples/basic/

ENTRYPOINT ["examples/basic/target/assemblies/bin/ServerExample1"]
