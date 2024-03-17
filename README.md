Bulk CLI execution script for Cisco Devices:

This script could be used to add multiple CLI commands to multiple Cisco IOSXE devices. It would need a CSV file having device IP address. 
It could modify the interface level configuration or global level configuration. 
For example, there could be a scenario where you need to add a CLI on few ports of all the switches in your network. You just need to have the CSV with device IP and port name listed. The script would push the CLI to all the mentioned ports. 

It will give you a summary of the device it managed to login along with their IP address and show if any device login failed due to reachability issues or authentication issues. 

To Download:

git clone https://github.com/gaur-samal/bulk_cli_exec_cisco_devices.git

with Proxy:
https_proxy=<your proxy>  git clone https://github.com/gaur-samal/bulk_cli_exec_cisco_devices.git
cd bulk_cli_exec_cisco_devices
chmod 700 modify_config.py

To run:
./modify_config.py ip.csv 

Enter the action (1 to add config, 2 to remove config): 1
Enter the device credentials: ( Please note, use the credential which is used by DNAC for managing devices, the credential should be same for all the devices mentioned in csv file)
Enter username: sdaadmin
Enter password: 
Enter the configuration to add (press Enter twice to finish):
Use 'vlanid' to indicate where the VLAN ID should be inserted.
Config: 
ip routing



