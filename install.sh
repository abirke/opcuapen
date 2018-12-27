#!/bin/bash

if [ ! $(which virtualenv) ]; then
  echo "virtualenv not found";
  exit 1
fi

if [[ ! -d .venv ]]; then
  virtualenv -p python3 .venv
fi
source .venv/bin/activate

# use virtualenved pip to install opcuapen
pip3 install .

# monkey-patch python-opcua in virtualenv for error message evaluation
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d '.' -f1,2)
git apply --reject --directory=.venv/lib/python${PYTHON_VERSION}/site-packages/ python-opcua-patch.diff
