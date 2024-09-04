import tkinter as tk
import tkinter.ttk as ttk
from tkinter.colorchooser import askcolor
import tkinter.messagebox
import socket
import struct
import threading
import time
import requests
import json
from collections import defaultdict

class Ağİzleme:
    def __init__(self, master):
        self.master = master
        self.master.title("Ağ İzleme")
        self.master.geometry("800x700")

        self.load_settings()

        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill="both", expand=True)

        self.upper_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.upper_frame, text="Ağ İzleme")

        self.upper_headers = ["IP Adresi", "Transfer hızı (paket/saniye)", "Ortalama Paket Boyutu (bayt)", "Toplam Paket Boyutu (KB)"]
        self.upper_table = ttk.Treeview(self.upper_frame, columns=self.upper_headers, show="headings", style="Custom.Treeview")
        self.upper_table.pack(fill="both", expand=True, side="left")

        self.upper_scrollbar = tk.Scrollbar(self.upper_frame, orient="vertical", command=self.upper_table.yview)
        self.upper_scrollbar.pack(fill="y", side="right")
        self.upper_table.configure(yscrollcommand=self.upper_scrollbar.set)

        for header in self.upper_headers:
            self.upper_table.heading(header, text=header)
            self.upper_table.column(header, width=200)

        self.settings_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.settings_frame, text="Ayarlar")

        self.create_settings_ui()


        self.paket_sayısı = defaultdict(int)
        self.paket_boyutları = defaultdict(list)
        self.son_zamanı = defaultdict(float)
        self.toplam_boyut = defaultdict(float)
        self.paketler = defaultdict(list)


        self.paket_thread = threading.Thread(target=self.paket_yakala, daemon=True)
        self.paket_thread.start()


        self.table_update_thread = threading.Thread(target=self.tabloyu_güncelle, daemon=True)
        self.table_update_thread.start()


        self.upper_table.bind("<Double-1>", self.on_upper_table_double_click)
        self.upper_table.bind("<Button-3>", self.on_upper_table_right_click)

    def load_settings(self):
        try:
            with open('ayarlar.json', 'r') as f:
                settings = json.load(f)
                self.bg_color = settings.get('background_color', '#333')
                self.fg_color = settings.get('foreground_color', '#fff')
                self.tab_color = settings.get('tab_color', '#555')
        except FileNotFoundError:
            self.bg_color = '#333'
            self.fg_color = '#fff'
            self.tab_color = '#555'

        style = ttk.Style()
        style.configure("Custom.Treeview", background=self.bg_color, foreground=self.fg_color, fieldbackground=self.bg_color)
        style.configure("Custom.Treeview.Heading", background=self.tab_color, foreground=self.fg_color)
        style.configure('TButton', background=self.bg_color, foreground=self.fg_color, padding=6)
        style.map('TButton', background=[('active', '#666')])

    def save_settings(self):
        settings = {
            'background_color': self.bg_color,
            'foreground_color': self.fg_color,
            'tab_color': self.tab_color
        }
        with open('ayarlar.json', 'w') as f:
            json.dump(settings, f)

    def create_settings_ui(self):
        ttk.Button(self.settings_frame, text="Arkaplan Rengi Seç", command=self.choose_bg_color).pack(pady=5)
        ttk.Button(self.settings_frame, text="Yazı Rengi Seç", command=self.choose_fg_color).pack(pady=5)
        ttk.Button(self.settings_frame, text="Sekme Rengi Seç", command=self.choose_tab_color).pack(pady=5)
        ttk.Button(self.settings_frame, text="Ayarları Kaydet", command=self.save_settings).pack(pady=20)

    def choose_bg_color(self):
        color = askcolor(color=self.bg_color)[1]
        if color:
            self.bg_color = color
            self.update_ui()

    def choose_fg_color(self):
        color = askcolor(color=self.fg_color)[1]
        if color:
            self.fg_color = color
            self.update_ui()

    def choose_tab_color(self):
        color = askcolor(color=self.tab_color)[1]
        if color:
            self.tab_color = color
            self.update_ui()

    def update_ui(self):
        self.upper_frame.configure(bg=self.bg_color)
        self.settings_frame.configure(bg=self.bg_color)

        self.upper_table.configure(style="Custom.Treeview")
        style = ttk.Style()
        style.configure("Custom.Treeview", background=self.bg_color, foreground=self.fg_color, fieldbackground=self.bg_color)
        style.configure("Custom.Treeview.Heading", background=self.tab_color, foreground=self.fg_color)
        style.configure('TButton', background=self.bg_color, foreground=self.fg_color, padding=6)
        style.map('TButton', background=[('active', '#666')])

        self.master.configure(bg=self.bg_color)

    def create_socket(self, protocol):

        try:
            if protocol == "TCP":
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            elif protocol == "UDP":
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            return s
        except Exception as e:
            print(f"Soket oluşturulurken bir hata oluştu: {e}")
            exit(1)

    def paket_yakala(self):
        s_tcp = self.create_socket("TCP")
        s_udp = self.create_socket("UDP")

        try:
            while True:
                packet, addr = s_tcp.recvfrom(65565)
                self.process_packet(packet, 'TCP')

                packet, addr = s_udp.recvfrom(65565)
                self.process_packet(packet, 'UDP')

                self.send_test_packet()

        except KeyboardInterrupt:
            print("Dinleme işlemi durduruldu.")
            s_tcp.close()
            s_udp.close()

    def send_test_packet(self):

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"Test Packet", ("127.0.0.1", 12345))
        s.close()

    def process_packet(self, packet, protocol_name):

        ip_header = packet[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4

        protocol = iph[6]
        src_address = socket.inet_ntoa(iph[8])

        packet_size = len(packet)

        self.paketler[src_address].append({
            "protocol": protocol_name,
            "size": packet_size,
            "timestamp": time.time()
        })

        current_time = time.time()
        last_time = self.son_zamanı.get(src_address, current_time)
        if current_time - last_time > 1:  # 1 saniyelik zaman dilimi
            self.paket_sayısı[src_address] = 1
            self.paket_boyutları[src_address] = [packet_size]  # Listeyi sıfırla ve yeni boyutu ekle
            self.toplam_boyut[src_address] += packet_size / 1024
            self.son_zamanı[src_address] = current_time
        else:
            self.paket_sayısı[src_address] += 1
            self.paket_boyutları[src_address].append(packet_size)
            self.toplam_boyut[src_address] += packet_size / 1024

    def get_ip_info(self, ip):
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json")
            data = response.json()
            country_code = data.get("country")
            country_name = requests.get(f"https://restcountries.com/v3.1/alpha/{country_code}").json()[0]["name"]["common"]
            data["country_name"] = country_name
            return data
        except Exception as e:
            print(f"IP bilgileri alınırken bir hata oluştu: {e}")
            return {}

    def show_ip_summary(self, ip):

        ip_info = self.get_ip_info(ip)

        if ip_info:
            country = ip_info.get("country_name", "Bilinmiyor")
            city = ip_info.get("city", "Bilinmiyor")
            org = ip_info.get("org", "Bilinmiyor")
        else:
            country = city = org = "Bilinmiyor"

        summary_text = f"Ülke: {country}\nŞehir: {city}\nİSS: {org}"

        tk.messagebox.showinfo("IP Bilgileri", summary_text)

    def show_ip_summary_from_menu(self):

        item = self.upper_table.selection()
        if item:
            ip = self.upper_table.item(item)["values"][0]  # IP adresi 1. sütundadır
            self.show_ip_summary(ip)

    def show_ip_packets(self, ip):

        window = tk.Toplevel(self.master)
        window.title(f"{ip} - Paketler")
        window.geometry("600x400")

        frame = tk.Frame(window)
        frame.pack(fill="both", expand=True)

        headers = ["Protokol", "Boyut (bayt)", "Zaman"]
        table = ttk.Treeview(frame, columns=headers, show="headings", style="Custom.Treeview")
        table.pack(fill="both", expand=True, side="left")

        scrollbar = tk.Scrollbar(frame, orient="vertical", command=table.yview)
        scrollbar.pack(fill="y", side="right")
        table.configure(yscrollcommand=scrollbar.set)

        for header in headers:
            table.heading(header, text=header)
            table.column(header, width=200)

        for packet in self.paketler[ip]:
            protocol = packet["protocol"]
            size = packet["size"]
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet["timestamp"]))
            table.insert("", "end", values=(protocol, size, timestamp))

    def on_upper_table_double_click(self, event):

        item = self.upper_table.selection()
        if item:
            ip = self.upper_table.item(item)["values"][0]
            self.show_ip_summary(ip)

    def on_upper_table_right_click(self, event):

        item = self.upper_table.selection()
        if item:
            ip = self.upper_table.item(item)["values"][0]
            self.context_menu.post(event.x_root, event.y_root)

    def tabloyu_güncelle(self):

        while True:
            current_time = time.time()


            self.upper_table.delete(*self.upper_table.get_children())
            for ip, packet_count in self.paket_sayısı.items():
                time_diff = current_time - self.son_zamanı[ip]
                if time_diff > 1:
                    packet_rate = 0
                    avg_packet_size = 0
                else:
                    packet_rate = max(0, packet_count / time_diff)
                    avg_packet_size = (sum(self.paket_boyutları[ip]) / len(self.paket_boyutları[ip])) if self.paket_boyutları[ip] else 0
                total_size = max(0, self.toplam_boyut[ip])
                self.upper_table.insert("", "end", values=(ip, f"{packet_rate:.2f}", f"{avg_packet_size:.2f}", f"{total_size:.2f}"))

            time.sleep(1)

if __name__ == "__main__":
    root = tk.Tk()
    app = Ağİzleme(root)
    root.mainloop()
