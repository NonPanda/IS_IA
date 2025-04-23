import nmap
import time
import json
import sys
import os
import argparse
from datetime import datetime

def parse_arguments():
    """Parse command line arguments if provided"""
    parser = argparse.ArgumentParser(description='Advanced Nmap Port Scanner')
    parser.add_argument('-t', '--target', help='Target IP or range (e.g., 192.168.1.1 or 192.168.1.0/24)')
    parser.add_argument('-s', '--scan-type', type=int, choices=[1, 2, 3], 
                       help='Scan type: 1-Quick, 2-Intense, 3-Full')
    parser.add_argument('-o', '--output-dir', default='scan_results', 
                       help='Directory to save results (default: scan_results)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show verbose output')
    parser.add_argument('--timeout', type=int, default=0, help='Timeout in seconds (0 = no timeout)')
    return parser.parse_args()


def get_scan_arguments(scan_type, is_admin=False):
    """Return appropriate scan arguments based on scan type and privileges"""
    if scan_type == 1:
        return '-T4 -Pn'
    elif scan_type == 2:
        version_intensity = 7 if is_admin else 5
        return f'-T4 -Pn -sV --version-intensity {version_intensity} -O'
    elif scan_type == 3:
        version_intensity = 9 if is_admin else 7
        return f'-T4 -Pn -sV --version-intensity {version_intensity} -O -p- --max-retries 2'
    else:
        return '-T4 -Pn'

def create_output_directory(output_dir):
    """Create output directory with timestamp"""
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    full_path = f"{output_dir}_{timestamp}"
    os.makedirs(full_path, exist_ok=True)
    return full_path

def print_scan_summary(nm, scan_time):
    """Print a summary of the scan results"""
    total_hosts = len(nm.all_hosts())
    total_ports = 0
    open_ports = 0
    
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            total_ports += len(ports)
            for port in ports:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports += 1
    
    print("\n" + "="*50)
    print(f"SCAN SUMMARY")
    print(f"Hosts scanned: {total_hosts}")
    print(f"Total ports checked: {total_ports}")
    print(f"Open ports found: {open_ports}")
    print(f"Scan duration: {scan_time:.2f} seconds")
    print("="*50)

def main():
    """Main function to run the port scanner"""
    args = parse_arguments()
    
    
    target = args.target if args.target else input("Enter the target IP or range (e.g., 192.168.1.1 or 192.168.1.0/24): ")
    
    if args.scan_type:
        scan_type = args.scan_type
    else:
        print("\nScan Types:")
        print("1: Quick Scan - Basic port scan with minimal probing")
        print("2: Intense Scan - Service version detection and OS detection")
        print("3: Full Scan - Comprehensive scan of all ports with version and OS detection")
        scan_type = input("Choose scan type (1-3): ")
        try:
            scan_type = int(scan_type)
            if scan_type not in [1, 2, 3]:
                raise ValueError
        except ValueError:
            print("Invalid choice. Defaulting to Quick Scan.")
            scan_type = 1
    
    arguments = get_scan_arguments(scan_type)
    
    if args.timeout > 0:
        arguments += f" --host-timeout {args.timeout}s"
    
    nm = nmap.PortScanner()
    
    output_dir = create_output_directory(args.output_dir)
    
    print(f"\nScan Configuration:")
    print(f"Target: {target}")
    print(f"Scan type: {scan_type} ({arguments})")
    print(f"Output directory: {output_dir}")
    print("\nStarting scan... (this may take a while)")
    
    try:
        start_time = time.time()
        nm.scan(hosts=target, arguments=arguments)
        end_time = time.time()
        scan_time = end_time - start_time
        print(f"Scan completed in {scan_time:.2f} seconds.")
        
        if nm.all_hosts():
            print("\nScan Results:")
            for host in nm.all_hosts():
                print(f"\nHost: {host} ({nm[host].hostname() or 'no hostname'})")
                print(f"State: {nm[host].state()}")
                
                if 'osmatch' in nm[host] and nm[host]['osmatch']:
                    print("\nOS Detection:")
                    for osmatch in nm[host]['osmatch'][:2]: 
                        print(f"OS: {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)")
                
                for proto in nm[host].all_protocols():
                    print(f"\nProtocol: {proto}")
                    ports = sorted(nm[host][proto].keys())
                    for port in ports:
                        port_info = nm[host][proto][port]
                        service = port_info['name']
                        state = port_info['state']
                        version = port_info.get('product', 'Unknown')
                        version_details = []
                        
                        if 'version' in port_info and port_info['version']:
                            version_details.append(f"ver: {port_info['version']}")
                        if 'extrainfo' in port_info and port_info['extrainfo']:
                            version_details.append(port_info['extrainfo'])
                        
                        version_str = f" ({' - '.join([version] + version_details)})" if version_details or version != 'Unknown' else ""
                        
                        if args.verbose or state == 'open':
                            print(f"Port: {port}/{proto}\tState: {state}\tService: {service}{version_str}")
            
            print_scan_summary(nm, scan_time)
            
            output_file_txt = os.path.join(output_dir, 'scan_results.txt')
            with open(output_file_txt, 'w') as f:
                f.write(f"Scan Results for {target}\n")
                f.write(f"Date/Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Scan Arguments: {arguments}\n")
                f.write(f"Scan Duration: {scan_time:.2f} seconds\n\n")
                
                for host in nm.all_hosts():
                    f.write(f"\nHOST: {host} ({nm[host].hostname() or 'no hostname'})\n")
                    f.write(f"STATE: {nm[host].state()}\n")
                    
                    if 'osmatch' in nm[host] and nm[host]['osmatch']:
                        f.write("\nOS DETECTION:\n")
                        for osmatch in nm[host]['osmatch']:
                            f.write(f"  - {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)\n")
                    
                    for proto in nm[host].all_protocols():
                        f.write(f"\nPROTOCOL: {proto}\n")
                        ports = sorted(nm[host][proto].keys())
                        for port in ports:
                            port_info = nm[host][proto][port]
                            service = port_info['name']
                            state = port_info['state']
                            product = port_info.get('product', 'Unknown')
                            extrainfo = port_info.get('extrainfo', '')
                            
                            version_str = f"{product}"

                            if extrainfo:
                                version_str += f" ({extrainfo})"
                            
                            f.write(f"  Port: {port}/{proto}\tState: {state}\n")
                            f.write(f"    Service: {service}\n")
            
            output_file_json = os.path.join(output_dir, 'scan_results.json')
            with open(output_file_json, 'w') as f:
                scan_data = {
                    'scan_info': {
                        'target': target,
                        'arguments': arguments,
                        'start_time': start_time,
                        'end_time': end_time,
                        'duration': scan_time
                    },
                    'results': nm._scan_result
                }
                json.dump(scan_data, f, indent=4)
            
            html_report = os.path.join(output_dir, 'scan_report.html')
            with open(html_report, 'w') as f:
                f.write(f'''<!DOCTYPE html>
<html>
<head>
    <title>Nmap Scan Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        .open {{ color: green; font-weight: bold; }}
        .filtered, .closed {{ color: #999; }}
        .host-info {{ background-color: #f9f9f9; padding: 10px; margin-bottom: 20px; border-left: 5px solid #333; }}
    </style>
</head>
<body>
    <h1>Nmap Scan Report</h1>
    <div class="host-info">
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Scan Type:</strong> {scan_type}</p>
        <p><strong>Arguments:</strong> {arguments}</p>
        <p><strong>Scan Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Duration:</strong> {scan_time:.2f} seconds</p>
    </div>
''')
                
                for host in nm.all_hosts():
                    hostname = nm[host].hostname() or 'No hostname'
                    f.write(f'''
    <h2>Host: {host} ({hostname})</h2>
    <p><strong>State:</strong> {nm[host].state()}</p>
''')
                    
                    if 'osmatch' in nm[host] and nm[host]['osmatch']:
                        f.write('''
    <h3>OS Detection</h3>
    <table>
        <tr>
            <th>OS</th>
            <th>Accuracy</th>
        </tr>
''')
                        for osmatch in nm[host]['osmatch']:
                            f.write(f'''
        <tr>
            <td>{osmatch['name']}</td>
            <td>{osmatch['accuracy']}%</td>
        </tr>
''')
                        f.write('    </table>\n')
                    
                    for proto in nm[host].all_protocols():
                        f.write(f'''
    <h3>Protocol: {proto}</h3>
    <table>
        <tr>
            <th>Port</th>
            <th>State</th>
            <th>Service</th>
        </tr>
''')
                        ports = sorted(nm[host][proto].keys())
                        for port in ports:
                            port_info = nm[host][proto][port]
                            service = port_info['name']
                            state = port_info['state']
                            product = port_info.get('product', '')
                            extrainfo = port_info.get('extrainfo', '')
                            
                            version_str = f"{product}"
                           
                            if extrainfo:
                                version_str += f" ({extrainfo})"
                            
                            state_class = state.lower()
                            
                            f.write(f'''
        <tr>
            <td>{port}/{proto}</td>
            <td class="{state_class}">{state}</td>
            <td>{service}</td>
        </tr>
''')
                        f.write('    </table>\n')
                
                f.write('''
</body>
</html>
''')
            
            print(f"\nResults saved to:")
            print(f" - Text file: {output_file_txt}")
            print(f" - JSON file: {output_file_json}")
            print(f" - HTML report: {html_report}")
            
        else:
            print("No hosts found or scan failed.")
    
    except nmap.PortScannerError as e:
        print(f"Nmap scan error: {e}")
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()