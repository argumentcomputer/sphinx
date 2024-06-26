import re

# Function to convert time strings to seconds
def convert_to_seconds(time_str):
    if time_str.endswith('m'):
        return float(time_str[:-2]) * 60
    elif time_str.endswith('ms'):
        return float(time_str[:-2]) / 1000
    elif time_str.endswith('µs'):
        return float(time_str[:-2]) / 1_000_000
    elif time_str.endswith('s'):
        return float(time_str[:-1])
    else:
        raise ValueError(f"Unknown time format: {time_str}")

# Function to parse a single line and return a tuple (description, time)
def parse_line(line):
    desc = line[:121].strip()
    pattern = re.compile(r'(.+?)\s+([\d.]+[a-zµ]+)')
    match = pattern.search(line[121:])
    if match:
        time = convert_to_seconds(match.group(2))
        return desc, time
    return None

# Function to process files line by line and compare traces
def compare_traces(file1, file2):
    with open(file1, 'r') as f1, open(file2, 'r') as f2:
        trace1_lines = f1.readlines()
        trace2_lines = f2.readlines()

    comparison_results = []

    for i, (line1, line2) in enumerate(zip(trace1_lines, trace2_lines)):
        parsed1 = parse_line(line1)
        parsed2 = parse_line(line2)
        
        if parsed1 and parsed2:
            desc1, time1 = parsed1
            desc2, time2 = parsed2
            if desc1 != desc2:
                continue
            comparison_results.append((i, desc1, time1, time2, abs(time2 - time1)))

    comparison_results.sort(key=lambda x: x[4], reverse=True)

    return comparison_results

# Function to print comparison results
def print_comparison_results(comparison_results):
    for i, desc, time1, time2, diff in comparison_results:
        print(f"#{i:3} | {desc:60} | Diff: {diff:.6f}s | Trace 1: {time1:.6f}s | Trace 2: {time2:.6f}s")

# Main function
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python compare_traces.py <trace_file1> <trace_file2>")
        sys.exit(1)

    file1 = sys.argv[1]
    file2 = sys.argv[2]

    comparison_results = compare_traces(file1, file2)
    print_comparison_results(comparison_results)
