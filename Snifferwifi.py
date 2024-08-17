import os
import subprocess
import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, ARP, IP, TCP
import threading

sniffing_enabled = True

def log_message(message):
    if gui:  # Check if the GUI exists
        log_display.insert(tk.END, f"{message}\n")
        log_display.see(tk.END)  # Automatically scroll to the bottom of the log

def packet_callback(packet):
    if ARP in packet:
        log_message(f"ARP Packet Detected: Source IP: {packet[ARP].psrc}, Source MAC: {packet[ARP].hwsrc} -> Destination IP: {packet[ARP].pdst}, Destination MAC: {packet[ARP].hwdst}")
    elif IP in packet and TCP in packet:
        log_message(f"TCP Packet Detected: Source IP: {packet[IP].src}, Source MAC: {packet.src} -> Destination IP: {packet[IP].dst}, Destination MAC: {packet.dst}")

def start_sniffing():
    global sniffing_enabled
    sniffing_enabled = True
    try:
        sniff(prn=packet_callback, store=0, stop_filter=lambda x: not sniffing_enabled)
    except Exception as e:
        log_message(f"Error during sniffing: {e}")

def stop_sniffing():
    global sniffing_enabled
    sniffing_enabled = False

gui = tk.Tk()
gui.title("Wi-Fi Sniffer")

start_button = tk.Button(gui, text="Start Sniffing", command=lambda: threading.Thread(target=start_sniffing).start())
start_button.pack(pady=10)

stop_button = tk.Button(gui, text="Stop Sniffing", command=stop_sniffing)
stop_button.pack(pady=5)

log_display_label = tk.Label(gui, text="Packet Log:")
log_display_label.pack()
log_display = scrolledtext.ScrolledText(gui, height=15, width=50, wrap=tk.WORD)
log_display.pack(pady=10)

gui.mainloop()