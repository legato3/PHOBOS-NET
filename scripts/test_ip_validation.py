import sys
import os

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from app.services.shared.helpers import validate_ip_input
except ImportError as e:
    print(f"Error importing validate_ip_input: {e}")
    sys.exit(1)

def test_valid_inputs():
    print("Testing valid inputs...")
    valid_ips = ["1.2.3.4", "192.168.1.1", "google.com", "my-host.local", "2001:db8::1"]
    for ip in valid_ips:
        try:
            assert validate_ip_input(ip) == ip
            print(f"  PASS: {ip}")
        except Exception as e:
            print(f"  FAIL: {ip} raised {e}")
            return False
    return True

def test_invalid_inputs():
    print("\nTesting invalid inputs...")
    invalid_inputs = [
        "-h",
        "--help",
        "; ls",
        "1.2.3.4; ls",
        "$(whoami)",
        "`whoami`",
        "| cat /etc/passwd",
        "1.2.3.4 && ls",
        "> output.txt",
        "&"
    ]
    for ip in invalid_inputs:
        try:
            validate_ip_input(ip)
            print(f"  FAIL: {ip} was NOT rejected")
            return False
        except ValueError as e:
            print(f"  PASS: {ip} rejected with: {e}")
        except Exception as e:
            print(f"  FAIL: {ip} raised unexpected {type(e).__name__}: {e}")
            return False
    return True

def main():
    if test_valid_inputs() and test_invalid_inputs():
        print("\nAll tests passed!")
        sys.exit(0)
    else:
        print("\nSome tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
