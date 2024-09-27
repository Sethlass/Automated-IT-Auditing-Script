import os  # To interact with the file system
import subprocess  # To run system commands and capture their output
import hashlib  # For generating hash values to check file integrity
import json  # To generate and save compliance reports in JSON format
import paramiko  # For SSH connections to remote servers
import re  # For pattern matching in log analysis
from datetime import datetime  # For timestamping the report

# Define compliance rules in a dictionary
# This dictionary specifies which files to check, expected hash values, firewall rules, and log analysis patterns
RULES = {
    "file_integrity": {
        "files_to_check": [  # List of files to check for integrity
            "C:\\Windows\\System32\\drivers\\etc\\hosts"
        ],
        # Dictionary of expected hash values for the files
        "expected_hashes": {
            "C:\\Windows\\System32\\drivers\\etc\\hosts": "55a51e982c31eed6b268cf59726dbbce"
        }
    },
    "firewall": {
        # List of ports that should be open for compliance
        "required_ports": [22, 80, 443],
        # List of ports that should be closed for security
        "forbidden_ports": [23, 3389]
    },
    "log_analysis": {
        # Log file to be analyzed
        "log_file": r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log",
        # Patterns to search for in the log file to detect suspicious activities
        "suspicious_patterns": [
            r"Unauthorized access",
            r"Failed login"
        ]
    }
}

# Dictionary to store the results of compliance checks
COMPLIANCE_REPORT = {}

def check_file_integrity():
    """Check critical files for integrity using hash comparison."""
    files_to_check = RULES["file_integrity"]["files_to_check"]
    expected_hashes = RULES["file_integrity"]["expected_hashes"]

    compliance_issues = []
    for file_path in files_to_check:
        # Check if the file exists
        if not os.path.isfile(file_path):
            compliance_issues.append(f"File {file_path} not found.")
            continue

        # Calculate the MD5 hash of the file's contents
        actual_hash = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
        expected_hash = expected_hashes.get(file_path)

        # Compare actual hash with the expected hash
        if actual_hash != expected_hash:
            compliance_issues.append(f"{file_path} has been modified. Expected hash: {expected_hash}, Actual hash: {actual_hash}")

    # Update the compliance report with the findings
    if compliance_issues:
        COMPLIANCE_REPORT["File Integrity"] = compliance_issues
    else:
        COMPLIANCE_REPORT["File Integrity"] = "All critical files are intact."

def check_network_security():
    """Check network security settings like firewall rules and open ports."""
    required_ports = RULES["firewall"]["required_ports"]
    forbidden_ports = RULES["firewall"]["forbidden_ports"]

    try:
        # Use netstat command to list all open ports on the system
        result = subprocess.check_output(['netstat', '-an']).decode('utf-8')
        # Extract the open port numbers from the command output
        open_ports = set(re.findall(r':(\d+)\s', result))
    except Exception as e:
        # Handle any errors that occur during the execution of the netstat command
        COMPLIANCE_REPORT["Network Security"] = f"Error checking network security: {str(e)}"
        return

    compliance_issues = []
    # Check if all required ports are open
    for port in required_ports:
        if str(port) not in open_ports:
            compliance_issues.append(f"Required port {port} is not open. Please ensure the service is running and the port is open in the firewall.")

    # Check if any forbidden ports are open
    for port in forbidden_ports:
        if str(port) in open_ports:
            compliance_issues.append(f"Forbidden port {port} is open. This port should be closed for security reasons.")

    # Update the compliance report with the findings
    if compliance_issues:
        COMPLIANCE_REPORT["Network Security"] = compliance_issues
    else:
        COMPLIANCE_REPORT["Network Security"] = "All network settings are compliant."

def analyze_logs():
    """Analyze logs for suspicious activities."""
    log_file = RULES["log_analysis"]["log_file"]
    patterns = RULES["log_analysis"]["suspicious_patterns"]

    # Check if the log file exists
    if not os.path.isfile(log_file):
        COMPLIANCE_REPORT["Log Analysis"] = f"Log file {log_file} not found. Ensure firewall logging is enabled."
        enable_firewall_logging()  # Try to enable firewall logging if not found
        return

    try:
        # Open and read the log file
        with open(log_file, 'r') as file:
            log_data = file.read()
    except Exception as e:
        # Handle any errors that occur during the reading of the log file
        COMPLIANCE_REPORT["Log Analysis"] = f"Error reading log file: {str(e)}"
        return

    compliance_issues = []
    # Search for suspicious patterns in the log file
    for pattern in patterns:
        matches = re.findall(pattern, log_data)
        if matches:
            compliance_issues.append(f"Pattern '{pattern}' found {len(matches)} times.")

    # Update the compliance report with the findings
    if compliance_issues:
        COMPLIANCE_REPORT["Log Analysis"] = compliance_issues
    else:
        COMPLIANCE_REPORT["Log Analysis"] = "No suspicious patterns found."

def enable_firewall_logging():
    """Enable firewall logging for analysis."""
    try:
        # Enable firewall logging through netsh command
        subprocess.check_call([
            'netsh', 'advfirewall', 'set', 'currentprofile', 'logging', 'filename', 'C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log'
        ])
        subprocess.check_call([
            'netsh', 'advfirewall', 'set', 'currentprofile', 'logging', 'maxfilesize', '4096'
        ])
        subprocess.check_call([
            'netsh', 'advfirewall', 'set', 'currentprofile', 'logging', 'logallowedconnections', 'enable'
        ])
        subprocess.check_call([
            'netsh', 'advfirewall', 'set', 'currentprofile', 'logging', 'logdroppedconnections', 'enable'
        ])
        print("Firewall logging enabled successfully.")
    except subprocess.CalledProcessError as e:
        # Handle any errors during the enabling of firewall logging
        COMPLIANCE_REPORT["Log Analysis"] = f"Failed to enable firewall logging: {str(e)}. Run the script as Administrator."

def check_remote_server(host, username, password, commands):
    """Check compliance on a remote server using SSH."""
    try:
        # Set up SSH connection
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password)

        # Execute each command on the remote server and collect output
        for command in commands:
            stdin, stdout, stderr = client.exec_command(command)
            result = stdout.read().decode()
            # Record the output of each command in the compliance report
            COMPLIANCE_REPORT[f"Remote {host} {command}"] = result.strip() or stderr.read().decode()

        # Close the SSH connection
        client.close()
    except paramiko.ssh_exception.NoValidConnectionsError:
        # Handle connection errors if SSH service is not running or port is closed
        COMPLIANCE_REPORT[f"Remote {host}"] = "Unable to connect: SSH service might not be running or port 22 is closed."
    except Exception as e:
        # Handle other exceptions during the SSH connection
        COMPLIANCE_REPORT[f"Remote {host}"] = f"Error: {str(e)}"

def generate_report():
    """Generate and save compliance report."""
    # Generate a unique filename for the report using the current date and time
    report_file = f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    # Save the compliance report to a JSON file
    with open(report_file, 'w') as report:
        json.dump(COMPLIANCE_REPORT, report, indent=4)
    print(f"Compliance report saved to {report_file}")

def main():
    """Run compliance checks and generate report."""
    print("Starting compliance checks...")
    
    # Perform local compliance checks for file integrity, network security, and log analysis
    check_file_integrity()
    check_network_security()
    analyze_logs()
    
    # Perform remote server compliance checks using SSH
    remote_server_info = {
        "host": input("Enter the remote server IP or hostname: "),  # Prompt user for remote server address
        "username": input("Enter SSH username: "),                  # Prompt user for SSH username
        "password": input("Enter SSH password: "),                  # Prompt user for SSH password
        "commands": [
            "cat /etc/ssh/sshd_config",  # Example command for Linux remote server
            "netstat -tuln",
            "cat /var/log/auth.log"
        ]
    }
    check_remote_server(**remote_server_info)
    
    # Generate and save the compliance report
    generate_report()
    print("Compliance checks completed.")

if __name__ == "__main__":
    main()
