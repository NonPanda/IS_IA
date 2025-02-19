import nmap
import time
import json

# Initialize the Nmap PortScanner object
nm = nmap.PortScanner()

# Interactive input for target
target = input("Enter the target IP or range (e.g., 192.168.1.1 or 192.168.1.0/24): ")

# Interactive input for scan type
scan_type = input("Choose scan type (1: Quick Scan, 2: Intense Scan, 3: Full Scan): ")
if scan_type == '1':
    arguments = '-T4 -Pn'  # Quick scan
elif scan_type == '2':
    arguments = '-T4 -Pn -sV -O'  # Intense scan with version and OS detection
elif scan_type == '3':
    arguments = '-T4 -Pn -sV -O -p-'  # Full scan (all ports)
else:
    print("Invalid choice. Defaulting to Quick Scan.")
    arguments = '-T4 -Pn'

# Perform the Nmap scan
print(f"\nScanning target: {target} with arguments: {arguments}")
try:
    start_time = time.time()
    nm.scan(hosts=target, arguments=arguments)
    end_time = time.time()
    print(f"Scan completed in {end_time - start_time:.2f} seconds.")

    # Display scan results
    if nm.all_hosts():
        print("\nScan Results:")
        for host in nm.all_hosts():
            print(f"\nHost: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")

            # OS detection results
            if 'osmatch' in nm[host]:
                print("\nOS Detection:")
                for osmatch in nm[host]['osmatch']:
                    print(f"OS: {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)")

            # Display open ports and services
            for proto in nm[host].all_protocols():
                print(f"\nProtocol: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    print(f"Port: {port}\tState: {nm[host][proto][port]['state']}\tService: {nm[host][proto][port]['name']}\tVersion: {nm[host][proto][port].get('version', 'N/A')}")
    else:
        print("No hosts found or scan failed.")

    # Save results to a file (text and JSON formats)
    output_file_txt = 'scan_results.txt'
    output_file_json = 'scan_results.json'

    with open(output_file_txt, 'w') as f:
        for host in nm.all_hosts():
            f.write(f"\nHost: {host} ({nm[host].hostname()})\n")
            f.write(f"State: {nm[host].state()}\n")
            if 'osmatch' in nm[host]:
                f.write("\nOS Detection:\n")
                for osmatch in nm[host]['osmatch']:
                    f.write(f"OS: {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)\n")
            for proto in nm[host].all_protocols():
                f.write(f"\nProtocol: {proto}\n")
                ports = nm[host][proto].keys()
                for port in ports:
                    f.write(f"Port: {port}\tState: {nm[host][proto][port]['state']}\tService: {nm[host][proto][port]['name']}\tVersion: {nm[host][proto][port].get('version', 'N/A')}\n")

    with open(output_file_json, 'w') as f:
        json.dump(nm._scan_result, f, indent=4)

    print(f"\nScan results saved to {output_file_txt} and {output_file_json}")


except nmap.PortScannerError as e:
    print(f"Nmap scan error: {e}")
except Exception as e:
    print(f"An error occurred: {e}")