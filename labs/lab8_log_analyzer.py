print("Analyzing logs...\n")

alert_count = 0

with open("network_log.txt", "r") as file:

    for line in file:

        if "ALERT" in line:

            print(f"ALERT found: {line.strip()}")
            alert_count += 1

print(f"\nTotal alerts detected: {alert_count}")
