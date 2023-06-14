"""
Description:
 Generates various reports from a gateway log file.

Usage:
 python log_investigation.py log_path

Parameters:
 log_path = Path of the gateway log file
"""
import log_analysis_lib
import pandas as pd

# Get the log file path from the command line
# Because this is outside of any function, log_path is a global variable
log_path = log_analysis_lib.get_file_path_from_cmd_line()

def main():
    # Determine how much traffic is on each port
    port_traffic = tally_port_traffic()

    # Per step 9, generate reports for ports that have 100 or more records
    for port, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(port)

    # Generate report of invalid user login attempts
    generate_invalid_user_report()

    # Generate log of records from source IP 220.195.35.40
    generate_source_ip_log('220.195.35.40')

def tally_port_traffic():
    """Produces a dictionary of destination port numbers (key) that appear in a 
    specified log file and a count of how many times they appear (value)

    Returns:
        dict: Dictionary of destination port number counts
    """
    #Complete function body per step 7
    dpt_logs = log_analysis_lib.filter_log_by_regex(log_path, r'DPT=(.+?) ')[1]
    
    dpt_tally = {}
    for dpt in dpt_logs:
        dpt_tally[dpt[0]] = dpt_tally.get(dpt[0], 0) + 1

    return dpt_tally

def generate_port_traffic_report(port_number):
    """Produces a CSV report of all network traffic in a log file for a specified 
    destination port number.

    Args:
        port_number (str or int): Destination port number
    """
    # Complete function body per step 8

    # Get data from records that contain the specified destination port
    data = log_analysis_lib.filter_log_by_regex(log_path, r'^(.+ \d+) (.{8}).*SRC=(.*?) DST=(.*?) .*SPT=(.*?) DPT=(.*?) ')[1]
    
    # Generate the CSV report
    df = pd.DataFrame(data)
    csv_filename = f"destination_port_{port_number}_report.csv"
    headings = ('Date', 'Time', 'Source IP Address', 'Destination IP Address', 'Source Port', 'Destination port')
    df.to_csv(csv_filename, index=False, header=headings)

    return

def generate_invalid_user_report():
    """Produces a CSV report of all network traffic in a log file that show
    an attempt to login as an invalid user.
    """
    # Get data from records that show attempted invalid user login
    data = log_analysis_lib.filter_log_by_regex(log_path, r'Invalid user (.*?) from (.*?) ')[1]

    # Generate the CSV report
    df = pd.DataFrame(data)
    csv_filename = "invalid_users_report.csv"
    headings = ('Date', 'Time', 'Username', 'IP address')
    df.to_csv(csv_filename, index=False, header=headings)

    return

def generate_source_ip_log(ip_address):
    """Produces a plain text .log file containing all records from a source log
    file that contain a specified source IP address.

    Args:
        ip_address (str): Source IP address
    """
    # Get all records that have the specified source IP address
    records = log_analysis_lib.filter_log_by_regex(log_path, 'SRC=' + ip_address.replace(".", r"\\.") + r'\b', ignore_case=False, print_records=False)[0]

    # Save all records to a plain text .log file
    log_filename = f"source_ip_{ip_address.replace('.', '_')}.log"
    with open(log_filename, 'w') as file:
        file.write('\n'.join(records))

    return

if __name__ == '__main__':
    main()