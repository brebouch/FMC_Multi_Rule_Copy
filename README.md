# Secure Firewall Multi Rule Edit

## Overview
This tool is a work in progress effort example of duplicating Cisco Secure Firewall rules within an existing Access Control Policy.

### Note
Please be aware this project is a proof of concept and is not expected to be used as a production application without due diligence.

## Requirements

1. API credentials to Cisco Secure Firewall Management Center
2. Compute resource with python3 installed

## Configuration

1. Clone the repository into the desired directory
2. cd into the cloned directory
3. Install dependencies, pip install -r requirements.txt
4. Run the following command with associated arguments:

```bash
python3 fmc_rule_copy.py ----hostname FMC_IP_HOSTNAME --username admin --password PASSWORD --acp FTDv-Access-Policy --rules 4,5,6, --modify_object DataCenter --object_new_name UpdatedDataCenter --object_new_value 172.16.88.0/24
```

Arguments: 
* --hostname, Hostname or IP of FMC
* --username, Username for authenticating with FMC
* --password, Password for authenticating with FMC
* --acp, Name of access control policy to duplicate rules from
* --rules, Comma seperated list of rule numbers without spaces
* --modify_object, Object name to be modified, must be IP, Network, Range
* --object_new_name, Previous value to be modified
* --object_new_value, Updated value of object
* --log_name, Name of log file to write
