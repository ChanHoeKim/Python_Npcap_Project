import csv
import threading
import queue
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox

from scapy.all import sniff, IP, TCP, UDP, conf


class PacketMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Npcap Packet Monitor")
        self.root.geometry("900x520")

        self.running = False
        self.packet_queue = queue.Queue()
        self.sniffer_thread = None

        self.csv_file = "packet_log.csv"

        self.create_widgets()
        self.init_csv()
        self.update_ui_loop()

    def create_widgets(self):
        top_frame = ttk.Frame(self.root)
        top_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(top_frame, text="BPF Filter").pack(side="left")

        self.filter_entry = ttk.Entry(top_frame, width=50)
        self.filter_entry.insert(0, "tcp or udp")
        self.filter_entry.pack(side="left", padx=8)

        self.start_button = ttk.Button(top_frame, text="시작", command=self.start_capture)
        self.start_button.pack(side="left", padx=4)

        self.stop_button = ttk.Button(top_frame, text="중지", command=self.stop_capture)
        self.stop_button.pack(side="left", padx=4)

        self.status_label = ttk.Label(self.root, text="대기 중")
        self.status_label.pack(anchor="w", padx=10)

        columns = ("time", "src", "dst", "proto", "sport", "dport", "size", "hex")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=105)

        self.tree.column("hex", width=230)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

    def init_csv(self):
        with open(self.csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["time", "src", "dst", "proto", "sport", "dport", "size", "hex"])

    def start_capture(self):
        if self.running:
            return

        self.running = True
        bpf_filter = self.filter_entry.get().strip() or "tcp or udp"
        self.status_label.config(text=f"캡처 중: {bpf_filter}")

        self.sniffer_thread = threading.Thread(
            target=self.capture_packets,
            args=(bpf_filter,),
            daemon=True
        )
        self.sniffer_thread.start()

    def stop_capture(self):
        self.running = False
        self.status_label.config(text="중지됨")

    def capture_packets(self, bpf_filter):
        try:
            sniff(
                filter=bpf_filter,
                prn=self.handle_packet,
                store=False,
                stop_filter=lambda p: not self.running
            )
        except Exception as e:
            self.running = False
            messagebox.showerror("캡처 오류", str(e))

    def handle_packet(self, pkt):
        if IP not in pkt:
            return

        proto = None
        sport = ""
        dport = ""
        payload = b""

        if TCP in pkt:
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            payload = bytes(pkt[TCP].payload)
        elif UDP in pkt:
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            payload = bytes(pkt[UDP].payload)
        else:
            return

        row = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "src": pkt[IP].src,
            "dst": pkt[IP].dst,
            "proto": proto,
            "sport": sport,
            "dport": dport,
            "size": len(payload),
            "hex": payload[:32].hex()
        }

        self.save_csv(row)
        self.packet_queue.put(row)

    def save_csv(self, row):
        with open(self.csv_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                row["time"],
                row["src"],
                row["dst"],
                row["proto"],
                row["sport"],
                row["dport"],
                row["size"],
                row["hex"]
            ])

    def update_ui_loop(self):
        while not self.packet_queue.empty():
            row = self.packet_queue.get()

            self.tree.insert(
                "",
                0,
                values=(
                    row["time"],
                    row["src"],
                    row["dst"],
                    row["proto"],
                    row["sport"],
                    row["dport"],
                    row["size"],
                    row["hex"]
                )
            )

            if len(self.tree.get_children()) > 300:
                last = self.tree.get_children()[-1]
                self.tree.delete(last)

        self.root.after(100, self.update_ui_loop)


if __name__ == "__main__":
    conf.use_pcap = True

    root = tk.Tk()
    app = PacketMonitorApp(root)
    root.mainloop()