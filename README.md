# OPCUApen

A testing tool for attacks against cryptography usage in implementations of OPC UA

## Prerequisites
Install the GNU Multiple Precision Arithmetic Library using Aptitude or [Homebrew](https://brew.sh/)

### Linux
```bash
sudo apt-get install libgmp-dev libmpfr-dev libmpc-dev
```

### Mac OS
Homebrew requires Ruby, check if it is installed
```bash
ruby -v
```
or install according to [Ruby Version manager (RVM)](http://rvm.io/). Then install [Homebrew](https://brew.sh/).

```bash
brew install libmpc
brew install mpfr
```

## Setup

OPCUApen is installed using Python 3 and pip
```bash
pip3 install --user virtualenv   # install virtualenv
./install.sh                     # install opcuapen in virtual environment
source .venv/bin/activate        # activate the virtual environment
opcuapen --help                  # see if opcuapen is executable
```


## Docker
Dockerized OPC UA implementations can be used for testing

* [OPC Foundation UA Java](https://github.com/opcfoundation/ua-java)
* [OPC Foundation UA Java (Bouncy Castle 1.60)](https://github.com/opcfoundation/ua-java)
  * Due to Maven _Dependency mediation_ (see [Introduction to the Dependency Mechanism](https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#Transitive_Dependencies)), the OPC UA server example uses Bouncy Castle 1.54, even though the UA Java stack has already updated to Bouncy Castle 1.60. A patch makes this container use Bouncy Castle 1.60 with the server example.
* [Eclipse Milo](https://github.com/eclipse/milo)
* [python-opcua](https://github.com/freeopcua/python-opcua)

## Usage
```bash
cd docker-opcfoundation-server
docker-compose up -d
opcuapen test
docker-compose down

cd ../docker-opcfoundation-server-bc160
docker-compose up -d
opcuapen test
docker-compose down
```

## Documentation
API documentation can be build using sphinx
```bash
sphinx-apidoc --ext-mathjax -eo docs opcuapen
cd docs
make html
```