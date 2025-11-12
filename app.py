import socket
import threading
from queue import Queue
import time
import sys
import ipaddress # Used for input validation

# --- 1. CONFIGURATION AND GLOBALS ---
THREAD_COUNT = 100 # High concurrency
TIMEOUT = 0.5      
q = Queue()
open_ports = []    # List to store results for the final report
target_ip = None 

# --- 2. CORE SCANNING FUNCTION (Finalized) ---
def port_scan(port):
    """Attempts to connect to a single port and identifies the service."""
    knocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    knocker.settimeout(TIMEOUT)
    
    try:
        result = knocker.connect_ex((target_ip, port))
        knocker.close()
        
        if result == 0:
            service_name = 'Unknown'
            try:
                # Look up the standard service name 
                service_name = socket.getservbyport(port, "tcp")
            except:
                pass 
                
            # Print the result immediately
            print(f"  [OPEN] Port {port:<5} | Service: {service_name.upper()}")
            # Store the result for the final summary
            open_ports.append((port, service_name)) 
            
    except:
        # Ignore all connection-level errors (host unreachable, etc.)
        pass

# --- 3. THE THREAD WORKER (Finalized) ---
def worker():
    """Worker function that pulls ports from the queue and scans them."""
    while True:
        try:
            # Use a timeout so threads don't hang if the queue is unexpectedly empty
            port = q.get(timeout=1) 
        except:
            return # Thread exits gracefully
        
        port_scan(port)
        q.task_done()

# --- 4. INPUT AND SETUP FUNCTION ---
def setup_scan():
    """Handles user input, DNS resolution, and range validation."""
    global target_ip # Needed to modify the global variable

    # --- Get Target and Resolve IP ---
    target_host = input("Enter Target Hostname or IP (e.g., google.com): ")
    try:
        # Resolves hostname to IP address once
        target_ip = socket.gethostbyname(target_host)
        print(f"\nTarget Resolved: {target_host} -> {target_ip}")
    except socket.gaierror:
        print(f"\n[ERROR] Could not resolve host: {target_host}. Exiting.")
        sys.exit(1)

    # --- Get Port Range ---
    while True:
        try:
            start_port = int(input("Enter STARTING port (e.g., 1): "))
            end_port = int(input("Enter ENDING port (e.g., 1024): "))
            
            if 1 <= start_port <= end_port <= 65535:
                # Load ports into the queue here, ready for the threads
                for port in range(start_port, end_port + 1):
                    q.put(port)
                return start_port, end_port
            else:
                print("[ERROR] Invalid port range. Ports must be between 1 and 65535.")
        except ValueError:
            print("[ERROR] Invalid input. Please enter numbers for ports.")

# --- 5. MAIN EXECUTION ---
if __name__ == '__main__':
    
    start_time = time.time()

    # Get inputs, resolve target, and populate queue
    start_port, end_port = setup_scan()

    total_ports = end_port - start_port + 1
    
    print("-" * 50)
    print(f"Starting Scan on {target_ip}...\n")
    print(f"Total Ports: {total_ports} | Threads: {THREAD_COUNT} | Timeout: {TIMEOUT}s")
    print("-" * 50)
    
    # Start the worker threads
    for _ in range(THREAD_COUNT):
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    # Wait for the queue to be fully processed
    q.join()
    
    end_time = time.time()
    
    # --- 6. FINAL SUMMARY REPORT ---
    print("\n" + "-" * 50)
    print("SCAN SUMMARY ")
    print(f"Target IP: {target_ip}")
    print(f"Ports Scanned: {total_ports}")
    print(f"Open Ports Found: {len(open_ports)}")
    print(f"Time Elapsed: {end_time - start_time:.2f} seconds")
    print("-" * 50)
    
    if open_ports:
        print("\nOpen Ports Details:")
        for port, service in open_ports:
            print(f"  > Port {port:<5} ({service.upper()})")
    
    print("-" * 50)
