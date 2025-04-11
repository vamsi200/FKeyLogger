event_device = "/dev/input/event4"
try:
    print(f"Opening {event_device}...")
    with open(event_device, "rb") as f:
        print(f"Reading from {event_device}")
        while True:
            data = f.read(24)
            if not data:
                break
            print(f"Read {len(data)} bytes")
except PermissionError:
    print(f"Permission denied!")
except FileNotFoundError:
    print(f"{event_device} not found.")
except Exception as e:
    print(f"Error reading {event_device}: {e}")
