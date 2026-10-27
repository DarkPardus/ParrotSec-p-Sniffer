#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Havayı Koklayan Adam
Modemin verdiği IP bloğunu otomatik algılar, nmap ile tarar ve
IP / ad / MAC / üretici / işletim sistemi / açık port listesini gösterir.

Gereksinimler (Parrot / Debian):
    sudo apt install python3-pyqt5 nmap policykit-1

Yalnızca kendi ağınızda veya izniniz olan ağlarda kullanın.
"""
import csv
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

from PyQt5.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt5.QtGui import QIcon, QPixmap, QFont
from PyQt5.QtWidgets import (
    QApplication, QCheckBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QProgressBar, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

APP_NAME = "Havayı Koklayan Adam"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGO_PATH = os.path.join(BASE_DIR, "parrot-security-512px.png")

COLUMNS = ["IP Adresi", "Ad", "MAC Adresi", "Üretici", "İşletim Sistemi", "Açık Portlar"]
UNPRIV_PROBES = "-PS21,22,23,25,53,80,135,139,443,445,3389,8080,8443"


# --------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# --------------------------------------------------------------------------
def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return ""


def detect_network():
    """Varsayılan ağ arayüzünden modemin verdiği ağı bulur."""
    out = run(["ip", "-4", "-o", "route", "show", "default"])
    m = re.search(r"default via (\S+) dev (\S+)", out)
    if not m:
        return None
    gateway, dev = m.group(1), m.group(2)
    out = run(["ip", "-4", "-o", "addr", "show", "dev", dev])
    m = re.search(r"inet (\S+)", out)
    if not m:
        return None
    iface = ipaddress.ip_interface(m.group(1))
    net = iface.network
    if net.prefixlen < 22:  # çok büyük ağları /24 ile sınırla
        net = ipaddress.ip_network(f"{iface.ip}/24", strict=False)
    mac = ""
    try:
        with open(f"/sys/class/net/{dev}/address") as f:
            mac = f.read().strip().upper()
    except OSError:
        pass
    return {"network": str(net), "ip": str(iface.ip), "gateway": gateway, "dev": dev, "mac": mac}


def arp_table():
    """Çekirdeğin ARP/komşu tablosundan IP -> MAC eşlemesi."""
    table = {}
    for line in run(["ip", "-4", "neigh"]).splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+) .*lladdr ([0-9a-fA-F:]{17})", line)
        if m:
            table[m.group(1)] = m.group(2).upper()
    return table


_vendors = None


def vendor_lookup(mac):
    """nmap-mac-prefixes dosyasından üretici adını bulur."""
    global _vendors
    if _vendors is None:
        _vendors = {}
        for path in ("/usr/share/nmap/nmap-mac-prefixes", "/usr/local/share/nmap/nmap-mac-prefixes"):
            if os.path.exists(path):
                with open(path, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.startswith("#") or len(line) < 8:
                            continue
                        parts = line.strip().split(None, 1)
                        if len(parts) == 2:
                            _vendors[parts[0].upper()] = parts[1]
                break
    return _vendors.get(mac.replace(":", "").upper()[:6], "")


def parse_xml(text, info, admin):
    root = ET.fromstring(text)
    arp = arp_table()
    rows = []
    for h in root.findall("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        ip = mac = vendor = ""
        for a in h.findall("address"):
            t = a.get("addrtype")
            if t == "ipv4":
                ip = a.get("addr")
            elif t == "mac":
                mac, vendor = a.get("addr", ""), a.get("vendor", "")
        if not mac:
            mac = arp.get(ip, "")
            if not mac and info and ip == info.get("ip"):
                mac = info.get("mac", "")
        if mac and not vendor:
            vendor = vendor_lookup(mac)

        names = [x.get("name") for x in h.findall("hostnames/hostname") if x.get("name")]
        name = names[0] if names else ""
        if info:
            if ip == info.get("gateway"):
                name = f"{name} (Modem)".strip()
            elif ip == info.get("ip"):
                name = f"{name} (Bu bilgisayar)".strip()

        osm = h.find("os/osmatch")
        if osm is not None:
            os_text = f"{osm.get('name')} (%{osm.get('accuracy')})"
        else:
            os_text = "Bilinmiyor" if admin else "Bilinmiyor (yönetici yetkisi gerekir)"

        ports, details = [], []
        for p in h.findall("ports/port"):
            s = p.find("state")
            if s is None or s.get("state") != "open":
                continue
            sv = p.find("service")
            svc = sv.get("name", "?") if sv is not None else "?"
            ports.append(f"{p.get('portid')}/{svc}")
            extra = ""
            if sv is not None:
                extra = " ".join(x for x in (sv.get("product"), sv.get("version")) if x)
            details.append(f"{p.get('portid')}/{p.get('protocol')}  {svc}  {extra}".rstrip())

        rows.append({
            "ip": ip, "name": name, "mac": mac, "vendor": vendor, "os": os_text,
            "ports": ", ".join(ports), "tooltip": "\n".join(details),
        })
    rows.sort(key=lambda r: ipaddress.ip_address(r["ip"]) if r["ip"] else 0)
    return rows


# --------------------------------------------------------------------------
# Tarama iş parçacığı
# --------------------------------------------------------------------------
class ScanThread(QThread):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished_ok = pyqtSignal(list)
    failed = pyqtSignal(str)

    def __init__(self, target, admin, info):
        super().__init__()
        self.target, self.admin, self.info = target, admin, info
        self.proc = None
        self.stopped = False

    def stop(self):
        self.stopped = True
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass

    def run(self):
        nmap = shutil.which("nmap")
        if not nmap:
            self.failed.emit("nmap bulunamadı. Kurmak için:\n  sudo apt install nmap")
            return
        cmd = []
        if self.admin and os.geteuid() != 0:
            pk = shutil.which("pkexec")
            if not pk:
                self.failed.emit("pkexec bulunamadı (sudo apt install policykit-1).")
                return
            cmd.append(pk)
        cmd += [nmap, "-T4", "-F", "-sV", "--version-light",
                "--stats-every", "2s", "-oX", "-"]
        cmd += ["-O", "--osscan-guess"] if self.admin else [UNPRIV_PROBES]
        cmd.append(self.target)

        self.status.emit(f"Taranıyor: {self.target}")
        lines = []
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, text=True)
            for line in self.proc.stdout:
                lines.append(line)
                m = re.search(r'<taskprogress[^>]*percent="(\d+(?:\.\d+)?)"', line)
                if m:
                    self.progress.emit(int(float(m.group(1))))
            self.proc.wait()
        except Exception as e:
            self.failed.emit(str(e))
            return

        if self.stopped:
            self.failed.emit("Tarama durduruldu.")
            return
        output = "".join(lines)
        a, b = output.find("<?xml"), output.rfind("</nmaprun>")
        try:
            if a < 0 or b < 0:
                raise ValueError("XML çıktısı yok")
            rows = parse_xml(output[a:b + len("</nmaprun>")], self.info, self.admin)
        except Exception:
            tail = [l.strip() for l in lines if l.strip() and not l.startswith("<")][-6:]
            if self.proc.returncode in (126, 127):
                tail.append("Yetkilendirme iptal edildi veya reddedildi.")
            self.failed.emit("Tarama tamamlanamadı:\n" + "\n".join(tail))
            return
        self.progress.emit(100)
        self.finished_ok.emit(rows)


# --------------------------------------------------------------------------
# Ana pencere
# --------------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1100, 600)
        self.thread = None
        self.info = detect_network()
        has_logo = os.path.exists(LOGO_PATH)
        if has_logo:
            self.setWindowIcon(QIcon(LOGO_PATH))

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        # Başlık
        head = QHBoxLayout()
        logo = QLabel()
        if has_logo:
            logo.setPixmap(QPixmap(LOGO_PATH).scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        head.addWidget(logo)
        titles = QVBoxLayout()
        title = QLabel(APP_NAME)
        f = QFont()
        f.setPointSize(18)
        f.setBold(True)
        title.setFont(f)
        sub = QLabel("Ağdaki cihazları kokla: ad, MAC, işletim sistemi ve açık portlar")
        sub.setEnabled(False)
        titles.addWidget(title)
        titles.addWidget(sub)
        head.addLayout(titles)
        head.addStretch()
        root.addLayout(head)

        # Kontroller
        ctl = QHBoxLayout()
        ctl.addWidget(QLabel("Hedef ağ:"))
        self.target = QLineEdit(self.info["network"] if self.info else "192.168.1.0/24")
        self.target.setMaximumWidth(200)
        ctl.addWidget(self.target)
        self.admin = QCheckBox("Yönetici yetkisiyle tara (İşletim sistemi tespiti)")
        self.admin.setChecked(os.geteuid() == 0)
        ctl.addWidget(self.admin)
        ctl.addStretch()
        self.btn_start = QPushButton("Taramayı Başlat")
        self.btn_stop = QPushButton("Durdur")
        self.btn_stop.setEnabled(False)
        self.btn_csv = QPushButton("CSV Kaydet")
        self.btn_csv.setEnabled(False)
        for b in (self.btn_start, self.btn_stop, self.btn_csv):
            ctl.addWidget(b)
        root.addLayout(ctl)

        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        root.addWidget(self.bar)

        # Tablo
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeToContents)
        hdr.setStretchLastSection(True)
        root.addWidget(self.table)

        self.statusBar().showMessage(
            f"Algılanan ağ: {self.info['network']}  |  Modem: {self.info['gateway']}"
            if self.info else "Ağ algılanamadı; hedefi elle girin.")

        self.btn_start.clicked.connect(self.start_scan)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_csv.clicked.connect(self.save_csv)

        QTimer.singleShot(400, self.start_scan)  # açılışta otomatik tara

    # ---- tarama ----
    def start_scan(self):
        if self.thread and self.thread.isRunning():
            return
        target = self.target.text().strip()
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            QMessageBox.warning(self, APP_NAME, "Geçerli bir ağ girin (örn. 192.168.1.0/24).")
            return
        self.table.setRowCount(0)
        self.bar.setValue(0)
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_csv.setEnabled(False)
        self.thread = ScanThread(target, self.admin.isChecked(), self.info)
        self.thread.progress.connect(self.bar.setValue)
        self.thread.status.connect(self.statusBar().showMessage)
        self.thread.finished_ok.connect(self.on_done)
        self.thread.failed.connect(self.on_fail)
        self.thread.start()

    def stop_scan(self):
        if self.thread:
            self.thread.stop()

    def reset_buttons(self):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def on_done(self, rows):
        self.table.setRowCount(len(rows))
        keys = ["ip", "name", "mac", "vendor", "os", "ports"]
        for r, row in enumerate(rows):
            for c, k in enumerate(keys):
                item = QTableWidgetItem(row[k])
                if k == "ports" and row["tooltip"]:
                    item.setToolTip(row["tooltip"])
                self.table.setItem(r, c, item)
        self.reset_buttons()
        self.btn_csv.setEnabled(bool(rows))
        self.statusBar().showMessage(f"Tarama bitti: {len(rows)} cihaz bulundu.")

    def on_fail(self, msg):
        self.reset_buttons()
        self.statusBar().showMessage(msg.splitlines()[0] if msg else "Hata")
        if "durduruldu" not in msg:
            QMessageBox.warning(self, APP_NAME, msg)

    def save_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "CSV Kaydet", "ag_taramasi.csv", "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(COLUMNS)
            for r in range(self.table.rowCount()):
                w.writerow([self.table.item(r, c).text() for c in range(self.table.columnCount())])
        self.statusBar().showMessage(f"Kaydedildi: {path}")

    def closeEvent(self, e):
        if self.thread and self.thread.isRunning():
            self.thread.stop()
            self.thread.wait(2000)
        e.accept()


# --------------------------------------------------------------------------
def install_desktop_entry():
    """KDE uygulama menüsüne kısayol ekler:  python3 havayi_koklayan_adam.py --kur"""
    apps = os.path.expanduser("~/.local/share/applications")
    os.makedirs(apps, exist_ok=True)
    entry = (
        "[Desktop Entry]\nType=Application\n"
        f"Name={APP_NAME}\nComment=Yerel ağ tarayıcı\n"
        f"Exec=python3 {os.path.join(BASE_DIR, 'havayi_koklayan_adam.py')}\n"
        f"Icon={LOGO_PATH}\nTerminal=false\nCategories=Network;Security;\n"
    )
    path = os.path.join(apps, "havayi-koklayan-adam.desktop")
    with open(path, "w", encoding="utf-8") as f:
        f.write(entry)
    os.chmod(path, 0o755)
    print("Kısayol oluşturuldu:", path)


def main():
    if "--kur" in sys.argv:
        install_desktop_entry()
        return
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setDesktopFileName("havayi-koklayan-adam")
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
