import re
import matplotlib.pyplot as plt

def read_timestamps(file_name):
    timestamps = {}
    with open(file_name, 'r') as file:
        for line in file:
            # Use regex to extract FileID and timestamp
            match = re.match(r'FileID:\s*(\d+)\s+.*Time:\s*(\d+)\s*ns', line)
            if match:
                file_id = int(match.group(1))
                timestamp_ns = int(match.group(2))
                timestamps[file_id] = timestamp_ns
    return timestamps

def calculate_latencies(sent_file, received_file):
    sent_timestamps = read_timestamps(sent_file)
    received_timestamps = read_timestamps(received_file)
    
    latencies_ms = []
    file_ids = []
    
    common_file_ids = set(sent_timestamps.keys()) & set(received_timestamps.keys())
    
    for file_id in sorted(common_file_ids):
        sent_time = sent_timestamps[file_id]
        received_time = received_timestamps[file_id]
        latency_ms = (received_time - sent_time) / 1e6  # Convert ns to ms
        latencies_ms.append(latency_ms)
        file_ids.append(file_id)
    
    return file_ids, latencies_ms, sent_timestamps, received_timestamps

def plot_latencies(file_ids, latencies_ms, output_file=None):
    plt.figure(figsize=(10, 6))
    plt.plot(file_ids, latencies_ms, marker='o', linestyle='-')
    plt.xlabel('FileID')
    plt.ylabel('Latency (ms)')
    plt.title('Latency per FileID')
    plt.grid(True)
    plt.tight_layout()
    if output_file:
        plt.savefig(output_file)
    plt.show()

def print_latencies(file_ids, latencies_ms):
    print("Latency Results:")
    for file_id, latency in zip(file_ids, latencies_ms):
        print(f"FileID: {file_id}, Latency: {latency:.3f} ms")

def output_time_differences(sent_timestamps, received_timestamps, output_file='log_timeline.txt'):
    with open(output_file, 'w') as file:
        file.write("Time Differences Between Send and Receive Times:\n")
        common_file_ids = set(sent_timestamps.keys()) & set(received_timestamps.keys())
        for file_id in sorted(common_file_ids):
            sent_time = sent_timestamps[file_id]
            received_time = received_timestamps[file_id]
            time_diff_ns = received_time - sent_time  # Calculate difference in ns
            time_diff_ms = time_diff_ns / 1e6  # Convert ns to ms
            file.write(f"FileID {file_id}: SendTime {sent_time} ns, ReceiveTime {received_time} ns, Difference: {time_diff_ns} ns ({time_diff_ms:.3f} ms)\n")
    print(f"Time differences have been written to {output_file}")

if __name__ == "__main__":
    sent_file = 'log_sent_timestamp.txt'
    received_file = 'log_received_timestamp.txt'
    file_ids, latencies_ms, sent_timestamps, received_timestamps = calculate_latencies(sent_file, received_file)
    print_latencies(file_ids, latencies_ms)
    output_time_differences(sent_timestamps, received_timestamps)
    plot_latencies(file_ids, latencies_ms)
    

