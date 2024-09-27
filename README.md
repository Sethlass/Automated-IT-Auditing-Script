# Automated-IT-Auditing-Script

# Overview
This Python-based compliance checker automates the process of evaluating system compliance against security and operational standards, particularly aligned with FISMA requirements. The script performs checks on file integrity, network security, and log analysis to identify potential compliance issues and generate detailed reports. This tool is essential for IT auditors and security professionals looking to ensure systems adhere to best practices and regulatory standards.

# Features
* File Integrity Check: Verifies the integrity of critical files using MD5 hash comparison to detect unauthorized modifications.
* Network Security Check: Analyzes open ports against required and forbidden rules to ensure secure network configurations.
* Log Analysis: Scans specified log files for suspicious patterns, such as unauthorized access or failed login attempts.
* Automated Reporting: Generates comprehensive JSON reports documenting compliance status and potential issues.

# Installation

1. Clone the Repository:

        git clone https://github.com/yourusername/it-auditing-script.git

2. Navigate to the Project Directory:

        cd it-auditing-script
   
3. Install Required Packages: Ensure you have Python installed. Then, install the necessary dependencies:

       pip install -r requirements.txt

4. Configure the Script:

* Open the compliance_checker.py file.
* Modify the RULES dictionary to set specific file paths, expected hash values, required/forbidden ports, and log file paths according to your environment.

# Usage

1. Run the Script: Execute the script from the command line:

         python compliance_checker.py
   
3. Check the Report: The script generates a JSON report with the compliance results. Check the report in the same directory:

        compliance_report_YYYYMMDD_HHMMSS.json

# Customization

Modify Compliance Rules:

* Edit the RULES dictionary to add, remove, or change the file paths, ports, and log patterns according to your compliance requirements.

Integrate with Other Tools:

* The script can be integrated into larger security or audit frameworks as part of an automated pipeline or scheduled task.

# Future Enhancements

* Support for Additional Compliance Standards: Expand to include checks for other standards like SOX, PCI-DSS, and HIPAA.
* Integration with Security Information and Event Management (SIEM): Automate log analysis and reporting through integration with SIEM systems.
* Real-time Alerts: Implement real-time alerting for detected compliance violations.

# Contributing

* If you'd like to contribute to this project, feel free to fork the repository and submit a pull request. Contributions are always welcome!

# License

* This project is licensed under the MIT License.

# Contact

* For more information, feel free to connect with me on LinkedIn @ Seth-Lassiter or email me at Sethlass1@gmail.com.





