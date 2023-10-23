# -*- codeing = utf-8 -*-
# @Time : 2023/10/20 23:17
# @Author ： PengXuanye
# @File : sniffer9.py
# @Software : PyCharm


# import psutil
#
# # 获取所有网络接口
# interfaces = psutil.net_if_addrs().keys()
#
# # 打印接口名称
# for interface in interfaces:
#     print(interface)

# -*- codeing = utf-8 -*-
# @Time : 2023/10/20 20:27
# @Author ： PengXuanye
# @File : sniffer.py
# @Software : PyCharm

import os  # Import os
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QComboBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QHBoxLayout, QWidget, QTextEdit, QHeaderView, QLineEdit, QSplitter, QLabel
from PyQt5.QtCore import Qt  # Import Qt
from scapy.all import *
import threading

class Sniffer(QMainWindow):
    def __init__(self, host_ip):  # Pass host_ip as a parameter
        super().__init__()
        self.host_ip = host_ip  # Store the host IP
        self.initUI()

    def initUI(self):
        self.setWindowTitle("PyQt5 Network Sniffer")
        self.setGeometry(100, 100, 1500, 900)  # Updated height

        mainLayout = QVBoxLayout()

        filterLayout = QHBoxLayout()

        protocolFilterLayout = QHBoxLayout()
        self.protocolLabel = QLabel("应用协议过滤器：", self)
        protocolFilterLayout.addWidget(self.protocolLabel)
        self.protocolComboBox = QComboBox(self)
        self.protocolComboBox.addItems(["All", "HTTP", "HTTPS", "FTP", "SMTP", "IMAP", "POP3", "DNS"])
        protocolFilterLayout.addWidget(self.protocolComboBox)
        filterLayout.addLayout(protocolFilterLayout)

        addressFilterLayout = QHBoxLayout()
        self.addressLabel = QLabel("地址过滤器：", self)
        addressFilterLayout.addWidget(self.addressLabel)
        self.addressComboBox = QComboBox(self)
        self.addressComboBox.addItems(["All", "IP地址", "Mac地址"])
        addressFilterLayout.addWidget(self.addressComboBox)
        self.filterLineEdit = QLineEdit(self)
        addressFilterLayout.addWidget(self.filterLineEdit)
        filterLayout.addLayout(addressFilterLayout)

        mainLayout.addLayout(filterLayout)

        buttonLayout = QHBoxLayout()

        self.startButton = QPushButton("Start Sniffing", self)
        self.startButton.clicked.connect(self.start_sniffing)
        buttonLayout.addWidget(self.startButton)

        self.stopButton = QPushButton("Stop Sniffing", self)
        self.stopButton.setDisabled(True)  # Initially disable the stopButton
        self.stopButton.clicked.connect(self.stop_sniffing)
        buttonLayout.addWidget(self.stopButton)

        self.resetButton = QPushButton("Reset", self)
        self.resetButton.clicked.connect(self.reset_table)
        buttonLayout.addWidget(self.resetButton)

        mainLayout.addLayout(buttonLayout)

        splitter = QSplitter()
        self.tableWidget = QTableWidget(self)
        self.tableWidget.setColumnCount(5)
        self.tableWidget.setHorizontalHeaderLabels(["源IP", "源端口", "目标IP", "目标端口", "报文长度"])
        self.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tableWidget.clicked.connect(self.show_packet_detail)
        splitter.addWidget(self.tableWidget)

        self.textEdit = QTextEdit(self)
        splitter.addWidget(self.textEdit)

        mainLayout.addWidget(splitter)

        self.hexDumpDisplay = QTextEdit(self)
        self.hexDumpDisplay.setReadOnly(True)
        self.hexDumpDisplay.setFixedHeight(200)  # Updated height
        mainLayout.addWidget(self.hexDumpDisplay)

        container = QWidget()
        container.setLayout(mainLayout)
        self.setCentralWidget(container)

        self.stop_sniffing_flag = False
        self.packets = []

    def sniff_thread(self, filter_str):
        sniff(prn=self.packet_callback, filter=filter_str, stop_filter=lambda x: self.stop_sniffing_flag)

    def packet_callback(self, packet):
        self.packets.append(packet)
        src_ip = packet["IP"].src if packet.haslayer("IP") else '-'
        dst_ip = packet["IP"].dst if packet.haslayer("IP") else '-'
        src_port = packet[1].sport if hasattr(packet[1], 'sport') else '-'
        dst_port = packet[1].dport if hasattr(packet[1], 'dport') else '-'
        length = len(packet)

        rowPosition = self.tableWidget.rowCount()
        self.tableWidget.insertRow(rowPosition)
        self.tableWidget.setItem(rowPosition, 0, QTableWidgetItem(src_ip))
        self.tableWidget.setItem(rowPosition, 1, QTableWidgetItem(str(src_port)))
        self.tableWidget.setItem(rowPosition, 2, QTableWidgetItem(dst_ip))
        self.tableWidget.setItem(rowPosition, 3, QTableWidgetItem(str(dst_port)))
        self.tableWidget.setItem(rowPosition, 4, QTableWidgetItem(str(length)))

        # Scroll the tableWidget to the bottom
        vScrollBar = self.tableWidget.verticalScrollBar()
        vScrollBar.setValue(vScrollBar.maximum())

    def start_sniffing(self):
        # Check if the host IP is provided
        if not self.host_ip:
            print("请提供主机IP以打开混杂模式")
            return

        # Open the host network interface in promiscuous mode
        os.system(f"sudo ifconfig wlan promisc")
        print("已经打开混杂模式")

        self.startButton.setDisabled(True)  # Disable the startButton
        self.stopButton.setEnabled(True)  # Enable the stopButton
        protocol = self.protocolComboBox.currentText().lower()
        if protocol == "all":
            filter_str = "ip"
        else:
            filter_str = {
                "http": "tcp port 80",
                "https": "tcp port 443",
                "ftp": "tcp port 21",
                "smtp": "tcp port 25",
                "imap": "tcp port 143",
                "pop3": "tcp port 110",
                "dns": "udp port 53"
            }.get(protocol, "ip")

        filter_type = self.addressComboBox.currentText()
        if filter_type == "IP地址":
            filter_str += f" and ip host {self.filterLineEdit.text().strip()}"
        elif filter_type == "Mac地址":
            filter_str += f" and ether host {self.filterLineEdit.text().strip()}"

        self.stop_sniffing_flag = False
        t = threading.Thread(target=self.sniff_thread, args=(filter_str,))
        t.start()

    def stop_sniffing(self):
        self.stop_sniffing_flag = True
        self.startButton.setEnabled(True)  # Enable the startButton after stopping sniffing
        self.stopButton.setDisabled(True)  # Disable the stopButton

        # Close the host network interface's promiscuous mode
        os.system(f"sudo ifconfig wlan -promisc")
        print("已经关闭混杂模式")

    def reset_table(self):
        self.tableWidget.setRowCount(0)
        self.textEdit.clear()
        self.hexDumpDisplay.clear()
        self.packets = []

    def show_packet_detail(self):
        row = self.tableWidget.currentRow()
        packet = self.packets[row]
        self.textEdit.clear()
        self.textEdit.append(packet.show(dump=True))
        self.textEdit.verticalScrollBar().setValue(self.textEdit.verticalScrollBar().minimum())  # Set scroll to the top
        self.hexDumpDisplay.clear()
        self.hexDumpDisplay.append('Hexdump:')
        self.hexDumpDisplay.append(hexdump(packet, dump=True))
        self.hexDumpDisplay.verticalScrollBar().setValue(
        self.hexDumpDisplay.verticalScrollBar().minimum())  # Set scroll to the top

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python sniffer9.py <host_ip>")
    else:
        host_ip = sys.argv[1]
        app = QApplication(sys.argv)
        mainWin = Sniffer(host_ip)
        mainWin.show()
        sys.exit(app.exec_())

