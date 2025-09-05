import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext, messagebox
from scapy.all import *
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import defaultdict
import threading
import time


traffic_data = defaultdict(int)
stop_sniffing = False
target_ip = ''
logfile = open(f"packet_log_{time.strftime('%Y%m%d_%H%M%S')}.txt", "a")


sniff_thread = threading.Thread(target=lambda: None)
sniff_thread.daemon = True

def packet_callback(packet):
    global stop_sniffing
    if stop_sniffing:
        return

    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            if src_ip == target_ip:
                traffic_data[src_ip] += 1

                log_message = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {src_ip} -> {packet[IP].dst} | "
                if packet.haslayer(TCP):
                    log_message += f"TCP | Port: {packet[TCP].dport}"
                elif packet.haslayer(UDP):
                    log_message += f"UDP | Port: {packet[UDP].dport}"
                else:
                    log_message += f"Other | {packet[IP].dst}"
                logfile.write(log_message + "\n")
                update_text_area(log_message)

                # Debug: Print packet details
                print(f"Captured packet: {log_message}")

    except Exception as e:
        print(f"Error processing packet: {e}")

def update_plot():
    global traffic_data
    ips = list(traffic_data.keys())
    counts = list(traffic_data.values())

    ax.clear()
    if ips and counts:
        ax.bar(ips, counts, color='teal')
        ax.set_title(f"Network Traffic for {target_ip}", fontsize=16, color='darkorange')
        ax.set_xlabel("Source IP", fontsize=12, color='lightblue')
        ax.set_ylabel("Packet Count", fontsize=12, color='lightblue')
        ax.tick_params(axis='x', rotation=45, colors='yellow')
    else:
        ax.text(0.5, 0.5, 'No Data', fontsize=12, ha='center')
    
    canvas.draw()

def start_capture():
    global sniff_thread, stop_sniffing, target_ip
    target_ip = target_ip_entry.get()

    if not target_ip:
        messagebox.showerror("Input Error", "Please enter a target IP address.")
        return

    stop_sniffing = False
    if not sniff_thread.is_alive():
        try:
            sniff_thread = threading.Thread(target=sniff, kwargs={'prn': packet_callback, 'count': 0})
            sniff_thread.daemon = True
            sniff_thread.start()
            status_var.set("Status: Capturing...")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start capture: {e}")

def stop_capture():
    global stop_sniffing
    stop_sniffing = True
    status_var.set("Status: Stopped")

def update_text_area(text):
    log_text_area.insert(tk.END, text + "\n")
    log_text_area.yview(tk.END)

def on_closing():
    global stop_sniffing
    stop_sniffing = True
    logfile.close()
    root.destroy()


fig = Figure(figsize=(10, 6), dpi=100)
ax = fig.add_subplot(111)


root = tk.Tk()
root.title("Network Monitor Tool")

root.configure(bg='#333333')


notebook = ttk.Notebook(root)
notebook.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)


capture_tab = ttk.Frame(notebook)
notebook.add(capture_tab, text="Capture")

tk.Label(capture_tab, text="Target IP Address:", font=("Arial", 14), bg='#333333', fg='white').pack(pady=10)
target_ip_entry = tk.Entry(capture_tab, width=40, font=("Arial", 12))
target_ip_entry.pack(pady=10)

# Start and Stop Buttons
button_frame = tk.Frame(capture_tab, bg='#333333')
button_frame.pack(pady=15)

start_button = tk.Button(button_frame, text="Start Capture", command=start_capture, bg='#4CAF50', fg='white', font=("Arial", 12, 'bold'))
start_button.pack(side=tk.LEFT, padx=10)

stop_button = tk.Button(button_frame, text="Stop Capture", command=stop_capture, bg='#f44336', fg='white', font=("Arial", 12, 'bold'))
stop_button.pack(side=tk.LEFT, padx=10)


log_text_area = scrolledtext.ScrolledText(capture_tab, width=60, height=20, bg='#1e1e1e', fg='white', font=("Courier New", 10))
log_text_area.pack(pady=10)


status_var = tk.StringVar()
status_var.set("Status: Idle")
status_label = tk.Label(capture_tab, textvariable=status_var, font=("Arial", 12), bg='#333333', fg='#4CAF50')
status_label.pack(pady=10)


graph_tab = ttk.Frame(notebook)
notebook.add(graph_tab, text="Graph")


canvas = FigureCanvasTkAgg(fig, master=graph_tab)
canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

def update_plot_canvas():
    try:
        update_plot()
        root.after(1000, update_plot_canvas)
    except Exception as e:
        print(f"Error updating plot: {e}")

root.after(1000, update_plot_canvas)


root.protocol("WM_DELETE_WINDOW", on_closing)


try:
    root.mainloop()
except Exception as e:
    print(f"Error running GUI: {e}")
