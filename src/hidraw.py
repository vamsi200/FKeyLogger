def read_hidraw(device_path="/dev/hidraw0"):
    try:
        with open(device_path, "rb") as f:
            print(f"Reading from {device_path}...")
            while True:
                data = f.read(8)
                print("Raw:", data.hex())
    except PermissionError:
        pass
    except FileNotFoundError:
        print(f"{device_path} not found.")
    except KeyboardInterrupt:
        print("\nStopped.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    read_hidraw("/dev/hidraw0")
