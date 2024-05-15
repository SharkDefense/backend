# Use this script to create a virtual environment and install the required packages

python3.11 -m venv --without-pip myenv
source myenv/bin/activate
curl https://bootstrap.pypa.io/get-pip.py | python
pip install -r requirements.txt
