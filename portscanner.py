import socket
import tkinter as tk
from tkinter import scrolledtext
import threading
from concurrent.futures import ThreadPoolExecutor
import platform

MAX_THREADS = 100

def check_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                write_output(f"[OPEN] Port {port}\n", "open")
            else:
                write_output(f"[CLOSED] Port {port}\n", "closed")
    except Exception as e:
        write_output(f"[ERROR] Port {port}: {e}\n", "error")

def scan_ports():
    output_box.configure(state='normal')
    output_box.delete(1.0, tk.END)

    host_input = ip_entry.get().strip()
    try:
        target_ip = socket.gethostbyname(host_input)
    except socket.gaierror:
        write_output("❌ Invalid IP or hostname\n", "error")
        output_box.configure(state='disabled')
        return

    try:
        start_port = int(start_port_entry.get())
        end_port = int(end_port_entry.get())
        if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port):
            raise ValueError
    except ValueError:
        write_output("❌ Invalid port range\n", "error")
        output_box.configure(state='disabled')
        return

    write_output(f"🔎 Scanning {host_input} ({target_ip}) from port {start_port} to {end_port}...\n\n", "info")

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(check_port, target_ip, port)

    write_output("\n✅ Scan complete.\n", "complete")
    output_box.configure(state='disabled')

def write_output(text, tag=None):
    output_box.configure(state='normal')
    output_box.insert(tk.END, text, tag)
    output_box.see(tk.END)
    output_box.update()
    output_box.configure(state='disabled')

def run_scan_thread(event=None):
    threading.Thread(target=scan_ports, daemon=True).start()

# 🖼 GUI Setup
window = tk.Tk()
window.title("🎯 PyPortScanner - Smart Edition")
window.geometry("800x600")  # Start small
window.minsize(800, 600)
window.configure(bg="#111111")
window.bind("<Return>", run_scan_thread)  # ⏎ Enter key runs scan

# Responsive layout config
window.columnconfigure(0, weight=1)
window.columnconfigure(1, weight=1)
window.rowconfigure(4, weight=1)

tk.Label(window, text="Target IP / Hostname:", bg="#111111", fg="#FFFFFF", font=("Consolas", 14)).grid(row=0, column=0, padx=20, pady=10, sticky='w')
ip_entry = tk.Entry(window, font=("Consolas", 14), width=40)
ip_entry.grid(row=0, column=1, padx=10, pady=10, sticky='w')

tk.Label(window, text="Start Port:", bg="#111111", fg="#FFFFFF", font=("Consolas", 14)).grid(row=1, column=0, padx=20, pady=10, sticky='w')
start_port_entry = tk.Entry(window, font=("Consolas", 14), width=10)
start_port_entry.grid(row=1, column=1, padx=10, pady=10, sticky='w')

tk.Label(window, text="End Port:", bg="#111111", fg="#FFFFFF", font=("Consolas", 14)).grid(row=2, column=0, padx=20, pady=10, sticky='w')
end_port_entry = tk.Entry(window, font=("Consolas", 14), width=10)
end_port_entry.grid(row=2, column=1, padx=10, pady=10, sticky='w')

scan_btn = tk.Button(window, text="🚀 Start Scan", font=("Consolas", 14, "bold"), bg="#00cc66", fg="black", command=run_scan_thread)
scan_btn.grid(row=3, column=1, pady=10, sticky='w')

output_box = scrolledtext.ScrolledText(window, wrap=tk.WORD, font=("Consolas", 12), bg="#1c1c1c", fg="#00ff00", insertbackground="white")
output_box.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=20, pady=20)
output_box.tag_config("info", foreground="#33ccff")
output_box.tag_config("open", foreground="#00ff00")
output_box.tag_config("closed", foreground="#888888")
output_box.tag_config("error", foreground="red")
output_box.tag_config("complete", foreground="#00cccc")
output_box.configure(state='disabled')

window.mainloop()
