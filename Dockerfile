FROM python:3.11-slim

WORKDIR /eset_integration

RUN apt-get update && apt-get install -y git

RUN pip install --upgrade pip

RUN pip install git+https://github.com/eset-enterprise-integration/integration.git@0.2.0

COPY . .

CMD ["python3", "main_wazuh.py"]