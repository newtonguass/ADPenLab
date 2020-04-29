# Setup for BloodHound- Window version
1. Install ZuluJDK 11 or OracleJDK 11
1. Go to neo4j.com/download and click on "Download Server"
1. Download the current version of neo4j Server for Windows, selecting either 32 or 64 bit
1. Extract the zip of Neo4j
1. Use cmd and cd to neo4j/bin, then execute neo4j.bat install-service
1. Start the Neo4j by typing ==net start neo4j==
1. Login to http://localhost:7474, use default username neo4j and password ner4j and change the password.
1. Download the BloodHound from https://github.com/BloodHoundAD/BloodHound/releases
1. Extract and execute BloodHound. Using default server bolt://localhost:7687 and the Neo4j username, password.

---
# Data collection

1. Install python3
1. pip install bloodhound
1. python -m bloodhound -u user -p password -d domain -ns dnsserver(ad)

---
# Data ingestion

1. Zip the output of python-bloodhound output
1. Drag and drop in the window BloodHound
1. Click queries and investigate the default query option