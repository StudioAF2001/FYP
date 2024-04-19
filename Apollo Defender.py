import json
import os.path
import re
import subprocess
import sys
import time
from datetime import datetime
from typing import List
import xmltodict
from PySide6 import QtWidgets, QtCore
from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QPushButton, QFileDialog, QSizePolicy, QTabWidget, QWidget, QFileSystemModel, QTreeView, \
    QVBoxLayout, QHBoxLayout, QLineEdit, QRadioButton, QLabel, QSpacerItem, QListWidget, QListWidgetItem


class ApolloDefender(QtWidgets.QWidget):
    def __init__(self):
        """
        Constructor for the ApolloDefender application
        """
        super().__init__()

        self.vuln_text = ""
        self.ip_addresses: List[str] = []
        self.vulnerabilities_list: List[str] = []
        self.vuln_arr_dict: List[dict] = []
        self.vuln_log_dict: List[dict] = []

        self.setWindowTitle("Apollo Defender")

        self.ApolloDefender = QTabWidget()
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tab3 = QWidget()

        self.ApolloDefender.addTab(self.tab1, "Main Menu")
        self.ApolloDefender.addTab(self.tab2, "Vulnerabilities")
        self.ApolloDefender.addTab(self.tab3, "Files")

        # spacers to create gaps between elements
        spacer1 = QSpacerItem(50, 10, QSizePolicy.Minimum, QSizePolicy.Expanding)
        spacer3 = QSpacerItem(1, 10, QSizePolicy.Minimum, QSizePolicy.Expanding)
        spacer4 = QSpacerItem(1, 50, QSizePolicy.Minimum, QSizePolicy.Expanding)

        # title label
        title_label = QLabel("APOLLO DEFENDER", alignment=QtCore.Qt.AlignCenter)
        title_label.setStyleSheet("""font: 25pt""")
        title_label.setFixedHeight(40)

        # label and ip address input box
        label1 = QLabel("Please Input IP Address & Subnet Mask OR URL of Target", alignment=QtCore.Qt.AlignCenter)
        label1.setStyleSheet("""font: 15pt""")
        label1.setFixedHeight(25)

        self.scan_input = QLineEdit("", alignment=QtCore.Qt.AlignCenter)
        self.scan_input.setFixedHeight(25)
        self.scan_input.setFixedWidth(150)
        self.scan_input.setPlaceholderText("IP address or URL")

        # radio buttons for selecting scan type
        scan_type_label = QLabel("Select Scan Type", alignment=QtCore.Qt.AlignCenter)
        scan_type_label.setFixedHeight(25)
        scan_type_label.setStyleSheet("""font: 15pt""")
        self.rb1 = QRadioButton("Normal Scan")
        self.rb2 = QRadioButton("Aggressive Scan")
        self.rb3 = QRadioButton("Stealth Scan")

        # CVSS score input box
        cvss_label = QLabel("Enter minimum CVSS score for CVE scan", alignment=QtCore.Qt.AlignCenter)
        cvss_label.setFixedHeight(25)
        cvss_label.setStyleSheet("""font: 15pt""")
        self.cvss_input = QLineEdit("", alignment=QtCore.Qt.AlignCenter)
        self.cvss_input.setFixedHeight(25)
        self.cvss_input.setFixedWidth(150)
        self.cvss_input.setPlaceholderText("CVSS score (example: 7.2)")

        # field to allow user to input desired file path for file output
        self.file_path_input = QLineEdit("", alignment=QtCore.Qt.AlignCenter)
        self.file_path_input.setPlaceholderText("Input file path or select from folder")
        self.file_path_input.textChanged.connect(self.on_file_path_changed)

        # adding button and button connection for opening FileDialog
        self.select_button = QPushButton("•••")
        self.select_button.clicked.connect(self.select_folder)

        # button to run scan
        self.run_scan_btn = QPushButton("Run Scan")
        self.run_scan_btn.clicked.connect(lambda: self.submit_ip())

        # results text
        self.text2 = QLineEdit("Run scan to show results", alignment=QtCore.Qt.AlignCenter)
        self.text2.setReadOnly(True)
        self.text2.setStyleSheet("""font: 20pt;, width: 150px""")

        # blank line that will be edited as scans etc. are completed
        self.text3 = QLineEdit("", alignment=QtCore.Qt.AlignCenter)
        self.text3.setReadOnly(True)
        self.text3.setStyleSheet("""font: 20pt;, width: 150px""")

        # create a button to generate the report that only appears when the scan is complete
        self.generate_report_button = QPushButton("Generate Report")
        self.generate_report_button.setFixedWidth(150)
        self.generate_report_button.setFixedHeight(50)
        self.generate_report_button.clicked.connect(self.generate_report)

        # creating layouts
        mainMenuLayout = QVBoxLayout(self)
        title_layout = QVBoxLayout(self)
        InputBoxWrapper = QVBoxLayout(self)
        InputBoxWrapper.setAlignment(QtCore.Qt.AlignCenter)
        InputBoxWrapper.addStretch(1)
        InputBoxLayout = QVBoxLayout(self)
        InputBoxLayout.setAlignment(QtCore.Qt.AlignCenter)
        InputBoxLayout.addStretch(1)
        RadioButtonWrapper = QVBoxLayout(self)
        RadioButtonWrapper.setAlignment(QtCore.Qt.AlignCenter)
        RadioButtonLayout = QVBoxLayout(self)
        RadioButtonLayout.addStretch(1)
        RadioButtonLayout.setAlignment(QtCore.Qt.AlignCenter)
        CVSSLayout = QVBoxLayout(self)
        CVSSLayout.setAlignment(QtCore.Qt.AlignCenter)
        CVSSInputLayout = QHBoxLayout(self)
        CVSSInputLayout.setAlignment(QtCore.Qt.AlignCenter)
        FileSelectionLayout = QHBoxLayout(self)
        self.BottomBoxesLayout = QHBoxLayout(self)
        UpdateBoxesLayout = QVBoxLayout(self)

        # adding widgets to layout1
        title_layout.addWidget(title_label)
        InputBoxLayout.addSpacerItem(spacer1)
        InputBoxLayout.addWidget(self.scan_input)

        # input box wrapper
        InputBoxWrapper.addSpacerItem(spacer4)
        InputBoxWrapper.addWidget(label1)
        InputBoxWrapper.addLayout(InputBoxLayout)
        InputBoxWrapper.addSpacerItem(spacer4)

        # adding widgets to UpdateBoxesLayout
        RadioButtonLayout.addWidget(self.rb1)
        RadioButtonLayout.addWidget(self.rb2)
        RadioButtonLayout.addWidget(self.rb3)
        RadioButtonLayout.addSpacerItem(spacer4)

        # radio button wrapper
        RadioButtonWrapper.addWidget(scan_type_label)
        RadioButtonWrapper.addLayout(RadioButtonLayout)

        # adding widgets to CVSSLayout
        CVSSLayout.addWidget(cvss_label)
        CVSSInputLayout.addWidget(self.cvss_input)
        CVSSLayout.addLayout(CVSSInputLayout)
        CVSSLayout.addSpacerItem(spacer4)

        # adding widgets to layout2
        FileSelectionLayout.addWidget(self.file_path_input)
        FileSelectionLayout.addWidget(self.select_button)

        # adding widgets to layout3
        UpdateBoxesLayout.addSpacerItem(spacer3)
        UpdateBoxesLayout.addWidget(self.run_scan_btn)
        UpdateBoxesLayout.addWidget(self.text2)

        self.BottomBoxesLayout.addWidget(self.text3)

        UpdateBoxesLayout.addLayout(self.BottomBoxesLayout)

        # adding all layouts to main layout
        mainMenuLayout.addLayout(title_layout)
        mainMenuLayout.addLayout(InputBoxWrapper)
        mainMenuLayout.addLayout(RadioButtonWrapper)
        mainMenuLayout.addLayout(CVSSLayout)
        mainMenuLayout.addLayout(FileSelectionLayout)
        mainMenuLayout.addLayout(UpdateBoxesLayout)

        self.tab1.setLayout(mainMenuLayout)

        # tab 2 layout
        tab_2_title = QLabel("Vulnerabilities", alignment=QtCore.Qt.AlignCenter)
        tab_2_title.setStyleSheet("""font: 20pt""")
        self.vulnerabilities_list = QListWidget()

        tab_2_layout = QVBoxLayout()
        tab_2_layout.addWidget(tab_2_title)
        tab_2_layout.addWidget(self.vulnerabilities_list)

        self.tab2.setLayout(tab_2_layout)

        tab_3_title = QLabel("All Scan Related Files", alignment=QtCore.Qt.AlignCenter)
        tab_3_title.setStyleSheet("""font: 20pt""")
        self.refresh_button = QPushButton("↻")
        self.refresh_button.setFixedWidth(50)
        self.refresh_button.clicked.connect(self.refresh_tree)

        self.model = QFileSystemModel()
        self.tree = QTreeView()
        self.tree.setModel(self.model)
        self.tree.setColumnWidth(0, 250)
        self.tree.setAlternatingRowColors(True)

        height = self.height()
        self.tree.setFixedHeight(height * 0.90)

        tab_3_title_layout = QHBoxLayout()
        tab_3_title_layout.addWidget(tab_3_title)
        tab_3_title_layout.addSpacerItem(spacer1)
        tab_3_title_layout.addWidget(self.refresh_button)

        tab_3_layout = QVBoxLayout()
        tab_3_layout.addLayout(tab_3_title_layout)
        tab_3_layout.addWidget(self.tree)

        self.tab3.setLayout(tab_3_layout)

        self.main_layout = QVBoxLayout(self)
        self.main_layout.addWidget(self.ApolloDefender)

        self.setLayout(self.main_layout)
        self.show()

    def submit_ip(self) -> None:
        """Submits IP address to run_nmap function. Includes error checking."""
        if (self.check_ip_addr() | self.check_url()) & self.check_file_path() & self.check_cvss_score():  # check to ensure that user input is valid before running scan
            self.text2.setText("Running Nmap scan")
            self.text2.repaint()
            self.run_nmap()
            self.text2.setText("Nmap scan complete")
            self.text2.repaint()
            time.sleep(2)
            self.text2.setText("CVE scan complete")
            self.text2.repaint()
        else:
            self.text2.setText("Scan failed. Check for correct IP address format and correct file path and try again")

    def select_folder(self) -> None:
        """Opens the File Dialog box, allowing the user to select output file path."""
        folder_path = QFileDialog.getExistingDirectory(self, 'Select Folder')
        if folder_path:
            self.file_path_input.setText(folder_path)

    def on_file_path_changed(self) -> None:
        """Updates the file path in the tree view when the user changes the file path in the input box."""
        path = self.file_path_input.text()
        if os.path.exists(path):
            self.model.setRootPath(path)
            self.tree.setRootIndex(self.model.index(path))

    def refresh_tree(self) -> None:
        """Refreshes the tree view when the refresh button is clicked."""
        path = self.file_path_input.text()
        self.model.setRootPath(path)
        self.tree.setRootIndex(self.model.index(path))

    def check_file_path(self) -> bool:
        """
        Checks if the file path selected by the user is valid

        :return: boolean value indicating whether the file path is valid or not
        :rtype: bool
        """
        file_path = self.file_path_input.text()
        if os.path.exists(file_path):
            self.text3.setText("File path is valid!")
            self.text3.repaint()
            return True
        else:
            self.text3.setText("The file path is invalid")
            self.text3.repaint()
            return False

    def check_ip_addr(self) -> bool:
        """
        Checks if the IP address input by the user meets the required format
        :return: bool indicating whether the IP address is valid or not
        :rtype: bool
        """
        ipAddr = self.scan_input.text()
        # regex to check if correct format for IP address has been entered
        ipv4_host_regex = re.compile(r'^\d{2,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        ipv4_subnet_regex = re.compile(r'^\d{2,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{2}$')
        ipv6_regex = re.compile(r'^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4})$')

        if ipv4_subnet_regex.match(ipAddr) or ipv6_regex.match(ipAddr) or ipv4_host_regex.match(ipAddr):
            return True
        else:
            return False

    def check_url(self) -> bool:
        """
        Checks if the URL input by the user is a valid URL
        :return: bool indicating whether the URL is valid or not
        :rtype: bool
        """
        url_regex = re.compile(r'^([^\s/?.#]+\.)+[^\s/?.#]+$')

        if url_regex.match(self.scan_input.text()):
            return True
        else:
            self.text3.setText("Invalid URL")
            self.text3.repaint()
            return False

    @staticmethod
    def sanitise_ip(ip_text) -> str:
        """
        Sanitises the IP address text by replacing any '/' or '\' characters with '_'
        This is used when a file needs to be saved with the IP address in the name
        :param ip_text:
        :type ip_text: str
        :return:  with '/' and '\' characters replaced with '_' eg. 192.168.1.0/24 -> 192.168.1.0_24
        :rtype: str
        """
        for char in ['/', '\\']:
            if char in ip_text:
                ip_text = ip_text.replace(char, '_')
        return ip_text

    def check_cvss_score(self) -> bool:
        """
        Checks if the CVSS score entered by the user is in the correct format
        :return: bool indicating whether the CVSS score is valid or not
        :rtype: bool
        """
        # regex to check if correct format for CVSS score has been entered
        cvss_score: str = self.cvss_input.text()
        cvss_score_regex = re.compile(r'^[0-9]\.[0-9]$')
        if cvss_score_regex.match(cvss_score):
            return True
        else:
            self.text3.setText("Invalid CVSS score format. Please enter a score between 0.0 and 10.0")
            self.text3.repaint()
            return False

    def run_nmap(self) -> None:
        """
        Runs selected nmap scan type and subsequent CVE and log scans
        :return: None
        """
        date_format: str = '%Y-%m-%d'
        date = datetime.now().strftime(date_format)
        ip_address: str = self.scan_input.text()
        ip_text: str = self.sanitise_ip(self.scan_input.text())

        path: str = self.file_path_input.text()
        output_file: str = path + f"/nmapscan_{ip_text}_{date}.xml"
        if self.rb1.isChecked():
            self.normal_scan(ip_address, output_file)
        elif self.rb2.isChecked():
            self.aggressive_scan(ip_address, output_file)
        elif self.rb3.isChecked():
            self.stealth_scan(ip_address, output_file)
        # Runs nmap scan on given IP address and saves output to nmap.xml

        self.text3.setText("Output of nmap scan saved to nmapscan.xml")
        xml_path: str = output_file
        json_path: str = path + f"/nmapscan_{ip_text}_{date}.json"
        xml_to_json(xml_path, json_path)
        self.run_cve_search(self.define_active_devices(json_path))
        self.run_cve_log(self.ip_addresses)

    @staticmethod
    def normal_scan(ip_address, output_file) -> None:
        """
        Runs a normal nmap scan on the given IP address and save the output to a file
        :param ip_address:
        :param output_file:
        :return: None
        """
        nmap_cmd: str = f"nmap -O -T4 -F -oX {output_file} {ip_address}"
        subprocess.call(nmap_cmd, shell=True)

    @staticmethod
    def aggressive_scan(ip_address, output_file) -> None:
        """
        Runs an aggressive nmap scan on the given IP address and save the output to a file
        :param ip_address:
        :param output_file:
        :return: None
        """
        nmap_cmd: str = f"nmap -O -T4 -A -oX {output_file} {ip_address}"
        subprocess.call(nmap_cmd, shell=True)

    @staticmethod
    def stealth_scan(ip_address, output_file) -> None:
        """
        Runs a stealth nmap scan on the given IP address and save the output to a file
        :param ip_address:
        :param output_file:
        :return: None
        """
        nmap_cmd: str = f"nmap -O -T4 -sS -oX {output_file} {ip_address}"
        subprocess.call(nmap_cmd, shell=True)

    # function to loop through active_devices array and run cve scans on each
    def run_cve_search(self, ip_addresses) -> None:
        """
        Loops through active_devices array and run cve scans on each
        :param ip_addresses: List[str] of IP addresses as defined by :func:`define_active_devices()`
        :return: None
        """
        date_format: str = '%Y-%m-%d'

        # print(f"IP addresses: {ip_addresses}")
        for ip_address in ip_addresses:
            date: str = datetime.now().strftime(date_format)
            path: str = self.file_path_input.text()
            output_file: str = path + f"/CVEscan_{ip_address}_{date}.xml"
            cvss_score: str = self.cvss_input.text()

            nmap_cmd: str = (f"nmap -sV -oX {output_file} --script vulners --script-args mincvss={cvss_score} "
                             f"{ip_address}")
            subprocess.call(nmap_cmd, shell=True)
            self.text3.setText("Output of CVE scan saved to CVEscan_[IpAddress]_[date].xml")
            self.text3.repaint()
            xml_path: str = output_file
            json_path: str = path + f"/CVEscan_{ip_address}_{date}.json"
            xml_to_json(xml_path, json_path)
            self.populate_vulnerabilities_list(True)
            self.BottomBoxesLayout.addWidget(self.generate_report_button)

    def run_cve_log(self, ip_addresses) -> None:
        """
        Runs a CVE scan to create the log files
        :param ip_addresses:
        :return: None
        """
        date_format: str = '%Y-%m-%d'

        for ip_address in ip_addresses:
            date: str = datetime.now().strftime(date_format)
            path: str = self.file_path_input.text()
            output_file: str = path + f"/log_{ip_address}_{date}.xml"

            nmap_cmd: str = (f"nmap -sV -oX {output_file} --script vulners --script-args mincvss=0.0 "
                             f"{ip_address}")
            subprocess.call(nmap_cmd, shell=True)
            xml_path: str = output_file
            json_path: str = path + f"/log_{ip_address}_{date}.json"
            xml_to_json(xml_path, json_path)
            self.populate_vulnerabilities_list(False)
            self.create_log_file()

    # function to iterate through the nmap json file and return a list of active devices
    def define_active_devices(self, json_data) -> List[str]:
        """
        Iterates through the nmap json file and return a list of active devices
        :param json_data:
        :return: List of IP addresses of active devices
        :rtype: List[str]
        """
        with open(json_data, 'r') as file:
            data = json.load(file)

        ip_addresses: List[str] = []
        hosts = data['nmaprun']['host']

        if isinstance(data['nmaprun']['host'], list):
            for host in hosts:
                try:
                    for address in host.get('address', []):
                        if address['@addrtype'] == 'ipv4':
                            ip_addresses.append(address['@addr'])
                except TypeError or KeyError:
                    pass
        else:
            try:
                ip_addresses = self.get_host_addresses(hosts)
            except TypeError or KeyError:
                pass

        return ip_addresses

    # function to address duplicate code fragment in define_active_devices
    def get_host_addresses(self, host) -> List[str]:
        """
        Extracts the IP addresses from the host dictionary
        :param host: JSON object containing the host information
        :return: List of IP addresses
        :rtype: List[str]
        """
        host_addresses = host['address']

        if isinstance(host_addresses, list):
            for address_entry in host_addresses:
                if address_entry['@addrtype'] == 'ipv4':
                    self.ip_addresses.append(address_entry['@addr'])
        elif isinstance(host_addresses, dict):
            if host_addresses['@addrtype'] == 'ipv4':
                self.ip_addresses.append(host_addresses['@addr'])
        else:
            try:
                address_dict = json.loads(host_addresses)
                if address_dict['@addrtype'] == 'ipv4':
                    self.ip_addresses.append(address_dict['@addr'])
            except (json.JSONDecodeError, TypeError):
                pass

        return self.ip_addresses

    def populate_vulnerabilities_list(self, flag: bool) -> None:
        """
        Populates the vulnerabilities list and GUI depending on the function that calls it
        :param flag: a flag to indicate whether the function is being called from the run_cve_search function or the run_cve_log function
        :return: None
        """
        # if flag = 1, then the function is being called from the run_cve_search function
        # else, the function is being called from the run_cve_log function
        date_format: str = '%Y-%m-%d'
        date: str = datetime.now().strftime(date_format)
        path: str = self.file_path_input.text()
        if flag:
            self.vulnerabilities_list.clear()  # clear the list widget before populating it with new data

        # for loop to load each host cve file
        for ipaddress in self.ip_addresses:

            if flag:
                with open(f"{path}/CVEscan_{ipaddress}_{date}.json", 'r') as file:
                    data = json.load(file)
            else:
                with open(f"{path}/log_{ipaddress}_{date}.json", 'r') as file:
                    data = json.load(file)

            flag2 = False

            ports = data['nmaprun']['host']['ports']['port']
            for port in ports:
                protocol = port['@protocol']
                port_number = port['@portid']
                serv_name = port['service']['@name']
                if 'script' not in port:
                    continue
                else:
                    script = port['script']
                    if isinstance(script, list):
                        try:
                            for script_elem in script:
                                if script_elem['@id'] == 'vulners':
                                    table = script_elem['table']['table']
                                    for elem in table:
                                        cve_info = self.extract_cve_info(elem)
                                        if flag:  # this means function is being called from run_cve_search
                                            flag2 = True  # we set second flag to 1 to indicate that we are adding to the GUI as well
                                        self.create_vuln_list_item(cve_info, ipaddress, protocol, port_number, serv_name, flag2)
                                        if flag:
                                            self.vulnerabilities_list.repaint()
                        except KeyError:
                            pass

                    elif isinstance(script, dict):
                        try:
                            table = port['script']['table']['table']
                            for elem in table:
                                cve_info = self.extract_cve_info(elem)
                                if flag:
                                    flag2 = True
                                self.create_vuln_list_item(cve_info, ipaddress, protocol, port_number, serv_name, flag2)
                                if flag:
                                    self.vulnerabilities_list.repaint()
                        except KeyError:
                            pass

        if flag:
            self.vulnerabilities_list.repaint()

    @staticmethod
    def extract_cve_info(elem) -> dict:
        """
        Extracts the CVE information from the JSON element provided
        :param elem: JSON element containing the CVE information to be extracted
        :return: dict of CVE information
        :rtype: dict
        """
        # create a dictionary that will map the key found in the JSON file to the corresponding value
        cve_info: dict = {}

        for entry in elem['elem']:
            if entry['@key'] == 'cvss':
                cve_info['CVSS'] = entry['#text']
            elif entry['@key'] == 'id':
                cve_info['ID'] = entry['#text']
            elif entry['@key'] == 'is_exploit':
                cve_info['is_exploit'] = entry['#text']
        return cve_info

    def create_vuln_list_item(self, cve_info, ipaddress, protocol, port_number, serv_name, flag: bool) -> None:
        """
        Creates a list item for the vulnerabilities list
        :param cve_info:
        :param ipaddress:
        :param protocol:
        :param port_number:
        :param serv_name:
        :param flag: flag to determine the source of the function call
        :return: None
        """
        vuln_dict = {
            'ipaddress': ipaddress,
            'protocol': protocol,
            'port_number': port_number,
            'serv_name': serv_name,
            'cvss': cve_info['CVSS'],
            'id': cve_info['ID'],
            'is_exploit': cve_info['is_exploit']
        }
        if flag:
            vuln_text: str = (f"IP address: {vuln_dict['ipaddress']}\nProtocol: {vuln_dict['protocol']}\n"
                              f"Port: {vuln_dict['port_number']}\nService: {vuln_dict['serv_name']}\n"
                              f"CVSS: {vuln_dict['cvss']}\nID: {vuln_dict['id']}\n"
                              f"Is an Exploit: {vuln_dict['is_exploit']}\n")

            self.vulnerabilities_list.setStyleSheet("QListWidget::item { border: 1px solid black;}")
            vulnerability = QListWidgetItem(self.vulnerabilities_list)
            vulnerability.setText(vuln_text)
            vulnerability.setFlags(vulnerability.flags() & ~Qt.ItemIsSelectable)
            vulnerability.setSizeHint(QSize(250, 150))
            self.vulnerabilities_list.addItem(vulnerability)

            self.vuln_arr_dict.append(vuln_dict)
        else:
            self.vuln_log_dict.append(vuln_dict)

    def generate_report(self) -> None:
        """
        Generates a report of the vulnerabilities found in the scan
        :return: None
        """
        date_format: str = '%Y-%m-%d'
        date: str = datetime.now().strftime(date_format)

        file_path = QFileDialog.getSaveFileName(self, 'Save File', f"Scan Log {date}", 'Text Files (*.txt)')
        target: str = self.scan_input.text()

        intro_text: str = f"Vulnerabilities found in scan of target {target} for date {date}:\n\n"

        if file_path:
            try:
                with open(file_path[0], 'w') as file:
                    file.write(intro_text)
                    for vuln in self.vuln_arr_dict:
                        file.write(f"IP address: {vuln['ipaddress']}\nProtocol: {vuln['protocol']}\n"
                                   f"Port: {vuln['port_number']}\nService: {vuln['serv_name']}\n"
                                   f"CVSS: {vuln['cvss']}\nID: {vuln['id']}\n"
                                   f"Is an Exploit: {vuln['is_exploit']}\n\n")
            except FileNotFoundError:
                self.text3.setText("Invalid file path/name. Please try again.")
                self.text3.repaint()

        self.text3.setText("Report generated successfully")
        self.text3.repaint()

    def create_log_file(self) -> None:
        """
        Creates a log file of the vulnerabilities found in the scan
        :return: None
        """
        date_format: str = '%Y-%m-%d'
        date: str = datetime.now().strftime(date_format)
        path: str = self.file_path_input.text()
        log_file: str = path + f"/log_{date}.txt"
        with open(log_file, 'w') as file:
            file.write("Log file for Apollo Defender\n")
            file.write(f"Date: {date}\n")
            file.write("Scan results:\n")
            for vuln in self.vuln_log_dict:
                file.write(f"IP address: {vuln['ipaddress']}\nProtocol: {vuln['protocol']}\n"
                           f"Port: {vuln['port_number']}\nService: {vuln['serv_name']}\n"
                           f"CVSS: {vuln['cvss']}\nID: {vuln['id']}\n"
                           f"Is an Exploit: {vuln['is_exploit']}\n\n")


# function to convert the nmap XML output to a JSON output for easier parsing
def xml_to_json(xml_path, json_path) -> None:
    """
    Converts the nmap XML output to a JSON output for easier parsing
    :param xml_path:
    :param json_path:
    :return: None
    """
    # Read the XML file and parse it into a dictionary
    with open(xml_path, 'r') as xml_file:
        xml_data = xml_file.read()
        xml_dict = xmltodict.parse(xml_data)

    # Convert the dictionary to JSON
    json_data = json.dumps(xml_dict, indent=2)

    # Write the JSON data to a file
    with open(json_path, 'w') as json_file:
        json_file.write(json_data)


if __name__ == '__main__':
    app = QtWidgets.QApplication([])

    widget = ApolloDefender()
    widget.resize(800, 600)
    widget.show()

    sys.exit(app.exec())
