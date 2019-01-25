FROM microsoft/dotnet:latest

RUN apt-get update
WORKDIR /opt/workspace/

RUN git clone https://github.com/opcfoundation/ua-.netstandard.git
WORKDIR ua-.netstandard/SampleApplications/Samples/NetCoreConsoleServer

ENTRYPOINT ["dotnet", "run", "--project", "NetCoreConsoleServer.csproj", "-a"]
