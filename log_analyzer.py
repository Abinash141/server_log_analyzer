import pandas as pd
import re
import matplotlib.pyplot as plt
from collections import Counter

def parse_log_file(log_file_path):
    log_pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
    
    logs = []
    with open(log_file_path, 'r') as file:
        for line in file:
            match = re.match(log_pattern, line)
            if match:
                logs.append({
                    'ip': match.group(1),
                    'timestamp': match.group(2),
                    'request': match.group(3),
                    'status_code': int(match.group(4)),
                    'bytes_sent': int(match.group(5)),
                    'referrer': match.group(6),
                    'user_agent': match.group(7)
                })
    
    return pd.DataFrame(logs)

def detect_brute_force_attacks(log_df, threshold=10):

    failed_logins = log_df[log_df['status_code'].isin([401, 403])]
    
    ip_failed_counts = failed_logins.groupby('ip').size().reset_index(name='failed_attempts')
    
    suspicious_ips = ip_failed_counts[ip_failed_counts['failed_attempts'] > threshold]
    
    return suspicious_ips

def identify_unusual_ips(log_df, top_n=10):

    ip_counts = log_df['ip'].value_counts().reset_index()
    ip_counts.columns = ['ip', 'request_count']
    top_ips = ip_counts.head(top_n)
    
    low_request_ips = ip_counts[ip_counts['request_count'] < ip_counts['request_count'].quantile(0.1)]
    
    return top_ips, low_request_ips

def visualize_trends(log_df):
    log_df['timestamp'] = pd.to_datetime(log_df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
    log_df.set_index('timestamp').resample('H').size().plot()
    plt.title('Requests Over Time')
    plt.xlabel('Time')
    plt.ylabel('Request Count')
    plt.show()
    

    top_ips, _ = identify_unusual_ips(log_df)
    top_ips.plot(kind='bar', x='ip', y='request_count', legend=False)
    plt.title('Top IPs by Request Count')
    plt.xlabel('IP Address')
    plt.ylabel('Request Count')
    plt.show()

def main(log_file_path):
    log_df = parse_log_file(log_file_path)
    brute_force_ips = detect_brute_force_attacks(log_df)
    print("Suspicious IPs (Brute-Force Attacks):")
    print(brute_force_ips)
    
    top_ips, low_request_ips = identify_unusual_ips(log_df)
    print("\nTop IPs by Request Count:")
    print(top_ips)
    print("\nIPs with Unusually Low Request Counts:")
    print(low_request_ips)
    visualize_trends(log_df)


if __name__ == "__main__":
    log_file_path = "access.log" 
    main(log_file_path)