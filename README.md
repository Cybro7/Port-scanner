# Port-scanner
A fast, multi-threaded port scanner with GUI, built in Python for educational and Red Team use.

PyPortScanner GUI

PyPortScanner is a fast, multi-threaded TCP port scanner written in Python with a simple and functional GUI.

This tool is created for educational purposes and Red Team practice in authorized environments only.

---

What This Tool Does

- Scans any IP address or hostname
- Multi-threaded port scanning for speed
- Displays which ports are open, closed, or unreachable
- Accepts any custom port range from 1 to 65535
- GUI automatically resizes when the window is maximized
- Pressing Enter will also start the scan

---

Important Notes

- This tool is a permitted utility and does not bypass any firewall
- If a firewall is active on the target system, some or all ports may appear closed
- This is not a hacking tool or exploit framework
- It simply checks port accessibility using allowed socket connections

---

Disclaimer

This tool is provided for learning and Red Team simulation in test environments.  
The developer is not responsible for:

- Any misuse of this tool
- Any damage caused by unauthorized scanning
- Any form of data theft or privacy invasion

If someone chooses to use this tool for illegal or unethical purposes, that is their sole responsibility.

---


![image](https://github.com/user-attachments/assets/a16c1d8a-2ab9-42a2-8c48-19c09fe60990)

How To Use

1. Run the script using Python 3
2. Enter the target IP or hostname
3. Enter the starting and ending ports to scan
4. Click "Start Scan" or press Enter
5. Results will appear in real-time, showing port statuses

 <pre> # Step 1: Clone the repository
 git clone https://github.com/Cybro7/Port-scanner.git

# Step 2: Create a virtual environment
 python -m venv venv

# Step 3: Activate the environment
# On Windows:
 venv\Scripts\activate
# On Mac/Linux:
 source venv/bin/activate

# Step 4: Install dependencies (if any)
 pip install tk

# Step 5: Run the app
 python portscanner.py </pre>

---

License

This project is licensed under the MIT License.

Use it for good. Improve it if you want. Respect the rules.

![Untitled design (2)](https://github.com/user-attachments/assets/74353cdf-d0f8-49e3-ab73-0e053f411ac9)


