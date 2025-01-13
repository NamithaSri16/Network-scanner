import os
import platform
import winreg
import psutil
import win32com.client
import scapy.all as scapy
import nmap
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from jinja2 import Template
import requests
import logging
 
# Configure logging
logging.basicConfig(filename='system_report.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to get basic OS information
def get_os_info():
    return {
        "OS Version": platform.version(),
        "OS Release": platform.release(),
        "OS Name": platform.system(),
        "Architecture": platform.architecture()[0]
    }

# Function to get .NET versions
def get_dotnet_versions():
    versions = []
    try:
        reg_path = r"SOFTWARE\Microsoft\NET Framework Setup\NDP"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
            for i in range(1024):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)
                    version = winreg.QueryValueEx(subkey, "Version")[0]
                    versions.append((subkey_name, version))
                except OSError:
                    break
    except Exception as e:
        logging.error(f"Error accessing .NET versions: {e}")
    return versions

# Function to get Windows Defender settings
def get_windows_defender_settings():
    try:
        wmi = win32com.client.GetObject('winmgmts:')
        defender_settings = wmi.InstancesOf('MSFT_MpPreference')
        settings = []
        for setting in defender_settings:
            settings.append({
                "Exclusions": setting.ExclusionProcessPaths,
                "Scan Schedule": setting.ScanSchedule
            })
        return settings
    except Exception as e:
        logging.error(f"Error accessing Windows Defender settings: {e}")
        return [{"Error": "Unable to retrieve Windows Defender settings. Ensure it is enabled and you have administrative privileges."}]

# Function to get firewall rules
def get_firewall_rules():
    try:
        firewall_rules = []
        firewall_policy = win32com.client.Dispatch('HNetCfg.FwPolicy2')
        rules = firewall_policy.Rules
        for rule in rules:
            firewall_rules.append({
                "Name": rule.Name,
                "Action": rule.Action,
                "Enabled": rule.Enabled
            })
        return firewall_rules
    except Exception as e:
        logging.error(f"Error accessing firewall rules: {e}")
        return []

# Function to get environment variables
def get_environment_variables():
    return dict(os.environ)

# Function to get file system info
def get_file_system_info():
    try:
        user_dirs = {
            "Downloads": os.path.expanduser("~/Downloads"),
            "Documents": os.path.expanduser("~/Documents"),
            "Desktop": os.path.expanduser("~/Desktop")  # Dynamically get the Desktop path
        }
        files_info = {dir_name: os.listdir(path) for dir_name, path in user_dirs.items() if os.path.exists(path)}
        return files_info
    except Exception as e:
        logging.error(f"Error accessing file system info: {e}")
        return {"Error": "Unable to retrieve file system information"}

# Function to get ARP table
def get_arp_table(subnet="192.168.1.0/24"):
    try:
        answered, _ = scapy.arping(subnet)
        arp_entries = [{'IP': pkt.psrc, 'MAC': pkt.hwsrc} for _, pkt in answered]
        return arp_entries
    except Exception as e:
        logging.error(f"Error accessing ARP table: {e}")
        return []

# Function to get network shares
def get_network_shares():
    shares = psutil.disk_partitions()
    return [share.device for share in shares]

# Function to get open ports
def get_open_ports(host='localhost'):
    try:
        nm = nmap.PortScanner()
        nm.scan(host, arguments='-T4')
        return nm.csv()  # You may need to parse this CSV for specific details
    except Exception as e:
        logging.error(f"Error scanning ports: {e}")
        return []

# Function to detect vulnerabilities using CVE
def get_cve_data(query):
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={query}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        cve_entries = data.get('result', {}).get('CVE_Items', [])
        vulnerabilities = [
            {
                "CVE ID": entry.get('cve', {}).get('CVE_data_meta', {}).get('ID', 'N/A'),
                "Description": entry.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', 'No description available')
            }
            for entry in cve_entries
        ]
        return vulnerabilities
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error accessing CVE data: {e}")
        return []
    except ValueError as e:
        logging.error(f"JSON parsing error: {e}")
        return []

# Function to generate PDF report
def generate_pdf_report(filename, content):
    try:
        c = canvas.Canvas(filename, pagesize=letter)
        width, height = letter
        text_object = c.beginText(100, height - 100)
        text_object.setFont("Helvetica", 10)
        for line in content.split('\n'):
            text_object.textLine(line)
        c.drawText(text_object)
        c.save()
    except Exception as e:
        logging.error(f"Error generating PDF report: {e}")

# Function to generate HTML report
def generate_html_report(filename, data):
    template = Template('''
    <html>
    <head><title>System Report</title></head>
    <body>
    <h1>System and Network Report</h1>
    <pre>{{ data }}</pre>
    </body>
    </html>
    ''')
    try:
        with open(filename, 'w') as file:
            file.write(template.render(data=data))
    except Exception as e:
        logging.error(f"Error generating HTML report: {e}")

# Main function to execute the script
def main():
    try:
        os_info = get_os_info()
        dotnet_versions = get_dotnet_versions()
        defender_settings = get_windows_defender_settings()
        firewall_rules = get_firewall_rules()
        env_vars = get_environment_variables()
        file_system_info = get_file_system_info()
        arp_table = get_arp_table()
        network_shares = get_network_shares()
        open_ports = get_open_ports()

        # Create a list of queries for CVE detection based on software and system info
        queries = ["OS " + os_info['OS Name']]
        for version in dotnet_versions:
            queries.append(".NET Framework " + version[1])
        
        # Collect CVE data
        cve_data = []
        for query in queries:
            cve_data.extend(get_cve_data(query))
        
        # Provide test data for CVE entries if none are found
        if not cve_data:
            cve_data = [
                {
                    "CVE ID": "CVE-2024-12345",
                    "Description": "This is a test CVE entry for demonstration purposes. It represents a hypothetical vulnerability."
                },
                {
                    "CVE ID": "CVE-2024-67890",
                    "Description": "Another test CVE entry. It is used to ensure that the report formatting is correct."
                }
            ]

        # Format CVE data for the report
        cve_data_formatted = "\n".join(
            f"CVE ID: {entry['CVE ID']}\nDescription: {entry['Description']}\n"
            for entry in cve_data
        )

        # Format report content
        report_content = (
            f"OS Info:\n{os_info}\n\n"
            f".NET Versions:\n{dotnet_versions}\n\n"
            f"Defender Settings:\n{defender_settings}\n\n"
            f"Firewall Rules:\n{firewall_rules}\n\n"
            f"Environment Variables:\n{env_vars}\n\n"
            f"File System Info:\n{file_system_info}\n\n"
            f"ARP Table:\n{arp_table}\n\n"
            f"Network Shares:\n{network_shares}\n\n"
            f"Open Ports:\n{open_ports}\n\n"
            f"CVE Data:\n{cve_data_formatted}\n"
        )

        # Generate reports
        generate_pdf_report("vulnerability_report.pdf", report_content)
        generate_html_report("vulnerability_report.html", report_content)

    except Exception as e:
        logging.error(f"Error in main function: {e}")

if __name__ == "__main__":
    main()
