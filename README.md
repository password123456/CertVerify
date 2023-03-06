# CertVerify
![made-with-python][made-with-python]
![Python Versions][pyversion-button]
[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Fpassword123456%2FCertVerify&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=hits&edge_flat=false)](https://hits.seeyoufarm.com)


[pyversion-button]: https://img.shields.io/pypi/pyversions/Markdown.svg
[made-with-python]: https://img.shields.io/badge/Made%20with-Python-1f425f.svg


The CertVerify is a tool designed to detect executable files (exe, dll, sys) that have been signed with untrusted or leaked code signing certificates. The purpose of this tool is to identify potentially malicious files that have been signed using certificates that have been compromised, stolen, or are not from a trusted source.


## Why is this tool needed?
Executable files signed with compromised or untrusted code signing certificates can be used to distribute malware and other malicious software. Attackers can use these files to bypass security controls and to make their malware appear legitimate to victims. This tool helps to identify these files so that they can be removed or investigated further.

As a continuous project of the previous [malware scanner](https://github.com/password123456/malwarescanner), i have created such a tool. This type of tool is also essential in the event of a security incident response.


## Scope of use and limitations
1. The CertVerify cannot guarantee that all files identified as suspicious are necessarily malicious. It is possible for files to be falsely identified as suspicious, or for malicious files to go undetected by the scanner.

2. The scanner only targets code signing certificates that have been identified as malicious by the public community. This includes certificates extracted by malware analysis tools and services, and other public sources. There are many unverified malware signing certificates, and it is not possible to obtain the entire malware signing certificate the tool can only detect some of them. For additional detection, you have to extract the certificate's serial number and fingerprint information yourself and add it to the signatures.


3. The scope of this tool does not include the extraction of code signing information for special rootkits that have already preempted and operated under the kernel, such as FileLess bootkits, or hidden files hidden by high-end technology. In other words, if you run this tool, it will be executed at the user level. Similar functions at the kernel level are more accurate with antirootkit or EDR. Please keep this in mind and focus on the ideas and principles... To implement the principle that is appropriate for the purpose of this tool, you need to development a driver(sys) and run it into the kernel with NT\SYSTEM privileges.

4. Nevertheless, if you want to run this tool in the event of a Windows system intrusion incident, and your purpose is sys files, boot into safe mode or another boot option that does not load the extra driver(sys) files (load only default system drivers) of the Windows system before running the tool. I think this can be a little more helpful.

5. Alternatively, mount the Windows system disk to the Linux and run the tool in the Linux environment. I think this could yield better results.


## Features
- File inspection based on leaked or untrusted certificate lists.
- Scanning includes subdirectories.
- Ability to define directories to exclude from scanning.
- Supports multiprocessing for faster job execution.
- Whitelisting based on certificate subject (e.g., Microsoft subject certificates are exempt from detection).
- Option to skip inspection of unsigned files for faster scans.
- Easy integration with SIEM systems such as Splunk by attaching scan_logs.
- Easy-to-handle and customizable code and function structure.


## And...
- Please let me know if any changes are required or if additional features are needed.
- If you find this helpful, please consider giving it a **"star"**:star2: to support further improvements.


## v1.0.0
- https://github.com/password123456/CertVerify/blob/main/CHANGES

## Preview
![preview](https://github.com/password123456/CertVerify/blob/main/preview.JPG)

## Scan result_log

```
datetime="2023-03-06 20:17:57",scan_id="87ea3e7b-dedc-4016-a43e-5c83f8d27c6e",os_version="Windows",hostname="DESKTOP-S5VJGLH",ip_address="192.168.0.23",infected_file="F:\code\pythonProject\certverify\test\chrome.exe",signature_hash="sha256",serial_number="0e4418e2dede36dd2974c3443afb5ce5",thumbprint="7d3d117664f121e592ef897973ef9c159150e3d736326e9cd2755f71e0febc0c",subject_name="Google LLC",issuer_name="DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",file_created_at="2023-03-03 23:20:41",file_modified_at="2022-04-14 06:17:04"
datetime="2023-03-06 20:17:58",scan_id="87ea3e7b-dedc-4016-a43e-5c83f8d27c6e",os_version="Windows",hostname="DESKTOP-S5VJGLH",ip_address="192.168.0.23",infected_file="F:\code\pythonProject\certverify\test\LineLauncher.exe",signature_hash="sha256",serial_number="0d424ae0be3a88ff604021ce1400f0dd",thumbprint="b3109006bc0ad98307915729e04403415c83e3292b614f26964c8d3571ecf5a9",subject_name="DigiCert Timestamp 2021",issuer_name="DigiCert SHA2 Assured ID Timestamping CA",file_created_at="2023-03-03 23:20:42",file_modified_at="2022-03-10 18:00:10"
datetime="2023-03-06 20:17:58",scan_id="87ea3e7b-dedc-4016-a43e-5c83f8d27c6e",os_version="Windows",hostname="DESKTOP-S5VJGLH",ip_address="192.168.0.23",infected_file="F:\code\pythonProject\certverify\test\LineUpdater.exe",signature_hash="sha256",serial_number="0d424ae0be3a88ff604021ce1400f0dd",thumbprint="b3109006bc0ad98307915729e04403415c83e3292b614f26964c8d3571ecf5a9",subject_name="DigiCert Timestamp 2021",issuer_name="DigiCert SHA2 Assured ID Timestamping CA",file_created_at="2023-03-03 23:20:42",file_modified_at="2022-04-06 10:06:28"
datetime="2023-03-06 20:17:59",scan_id="87ea3e7b-dedc-4016-a43e-5c83f8d27c6e",os_version="Windows",hostname="DESKTOP-S5VJGLH",ip_address="192.168.0.23",infected_file="F:\code\pythonProject\certverify\test\TWOD_Launcher.exe",signature_hash="sha256",serial_number="073637b724547cd847acfd28662a5e5b",thumbprint="281734d4592d1291d27190709cb510b07e22c405d5e0d6119b70e73589f98acf",subject_name="DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA",issuer_name="DigiCert Trusted Root G4",file_created_at="2023-03-03 23:20:42",file_modified_at="2022-04-07 09:14:08"
datetime="2023-03-06 20:18:00",scan_id="87ea3e7b-dedc-4016-a43e-5c83f8d27c6e",os_version="Windows",hostname="DESKTOP-S5VJGLH",ip_address="192.168.0.23",infected_file="F:\code\pythonProject\certverify\test\VBoxSup.sys",signature_hash="sha256",serial_number="2f451139512f34c8c528b90bca471f767b83c836",thumbprint="3aa166713331d894f240f0931955f123873659053c172c4b22facd5335a81346",subject_name="VirtualBox for Legacy Windows Only Timestamp Kludge 2014",issuer_name="VirtualBox for Legacy Windows Only Timestamp CA",file_created_at="2023-03-03 23:20:43",file_modified_at="2022-10-11 08:11:56"
datetime="2023-03-06 20:31:59",scan_id="f71277c5-ed4a-4243-8070-7e0e56b0e656",os_version="Windows",hostname="DESKTOP-S5VJGLH",ip_address="192.168.0.23",infected_file="F:\code\pythonProject\certverify\test\chrome.exe",signature_hash="sha256",serial_number="0e4418e2dede36dd2974c3443afb5ce5",thumbprint="7d3d117664f121e592ef897973ef9c159150e3d736326e9cd2755f71e0febc0c",subject_name="Google LLC",issuer_name="DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",file_created_at="2023-03-03 23:20:41",file_modified_at="2022-04-14 06:17:04"
datetime="2023-03-06 20:32:00",scan_id="f71277c5-ed4a-4243-8070-7e0e56b0e656",os_version="Windows",hostname="DESKTOP-S5VJGLH",ip_address="192.168.0.23",infected_file="F:\code\pythonProject\certverify\test\LineLauncher.exe",signature_hash="sha256",serial_number="0d424ae0be3a88ff604021ce1400f0dd",thumbprint="b3109006bc0ad98307915729e04403415c83e3292b614f26964c8d3571ecf5a9",subject_name="DigiCert Timestamp 2021",issuer_name="DigiCert SHA2 Assured ID Timestamping CA",file_created_at="2023-03-03 23:20:42",file_modified_at="2022-03-10 18:00:10"
datetime="2023-03-06 20:32:00",scan_id="f71277c5-ed4a-4243-8070-7e0e56b0e656",os_version="Windows",hostname="DESKTOP-S5VJGLH",ip_address="192.168.0.23",infected_file="F:\code\pythonProject\certverify\test\LineUpdater.exe",signature_hash="sha256",serial_number="0d424ae0be3a88ff604021ce1400f0dd",thumbprint="b3109006bc0ad98307915729e04403415c83e3292b614f26964c8d3571ecf5a9",subject_name="DigiCert Timestamp 2021",issuer_name="DigiCert SHA2 Assured ID Timestamping CA",file_created_at="2023-03-03 23:20:42",file_modified_at="2022-04-06 10:06:28"
datetime="2023-03-06 20:32:01",scan_id="f71277c5-ed4a-4243-8070-7e0e56b0e656",os_version="Windows",hostname="DESKTOP-S5VJGLH",ip_address="192.168.0.23",infected_file="F:\code\pythonProject\certverify\test\TWOD_Launcher.exe",signature_hash="sha256",serial_number="073637b724547cd847acfd28662a5e5b",thumbprint="281734d4592d1291d27190709cb510b07e22c405d5e0d6119b70e73589f98acf",subject_name="DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA",issuer_name="DigiCert Trusted Root G4",file_created_at="2023-03-03 23:20:42",file_modified_at="2022-04-07 09:14:08"
datetime="2023-03-06 20:32:02",scan_id="f71277c5-ed4a-4243-8070-7e0e56b0e656",os_version="Windows",hostname="DESKTOP-S5VJGLH",ip_address="192.168.0.23",infected_file="F:\code\pythonProject\certverify\test\VBoxSup.sys",signature_hash="sha256",serial_number="2f451139512f34c8c528b90bca471f767b83c836",thumbprint="3aa166713331d894f240f0931955f123873659053c172c4b22facd5335a81346",subject_name="VirtualBox for Legacy Windows Only Timestamp Kludge 2014",issuer_name="VirtualBox for Legacy Windows Only Timestamp CA",file_created_at="2023-03-03 23:20:43",file_modified_at="2022-10-11 08:11:56"
datetime="2023-03-06 20:33:45",scan_id="033976ae-46cb-4c2e-a357-734353f7e09a",os_version="Windows",hostname="DESKTOP-S5VJGLH",ip_address="192.168.0.23",infected_file="F:\code\pythonProject\certverify\test\chrome.exe",signature_hash="sha256",serial_number="0e4418e2dede36dd2974c3443afb5ce5",thumbprint="7d3d117664f121e592ef897973ef9c159150e3d736326e9cd2755f71e0febc0c",subject_name="Google LLC",issuer_name="DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",file_created_at="2023-03-03 23:20:41",file_modified_at="2022-04-14 06:17:04"
datetime="2023-03-06 20:33:45",scan_id="033976ae-46cb-4c2e-a357-734353f7e09a",os_version="Windows",hostname="DESKTOP-S5VJGLH",ip_address="192.168.0.23",infected_file="F:\code\pythonProject\certverify\test\LineLauncher.exe",signature_hash="sha256",serial_number="0d424ae0be3a88ff604021ce1400f0dd",thumbprint="b3109006bc0ad98307915729e04403415c83e3292b614f26964c8d3571ecf5a9",subject_name="DigiCert Timestamp 2021",issuer_name="DigiCert SHA2 Assured ID Timestamping CA",file_created_at="2023-03-03 23:20:42",file_modified_at="2022-03-10 18:00:10"
datetime="2023-03-06 20:33:45",scan_id="033976ae-46cb-4c2e-a357-734353f7e09a",os_version="Windows",hostname="DESKTOP-S5VJGLH",ip_address="192.168.0.23",infected_file="F:\code\pythonProject\certverify\test\LineUpdater.exe",signature_hash="sha256",serial_number="0d424ae0be3a88ff604021ce1400f0dd",thumbprint="b3109006bc0ad98307915729e04403415c83e3292b614f26964c8d3571ecf5a9",subject_name="DigiCert Timestamp 2021",issuer_name="DigiCert SHA2 Assured ID Timestamping CA",file_created_at="2023-03-03 23:20:42",file_modified_at="2022-04-06 10:06:28"
datetime="2023-03-06 20:33:46",scan_id="033976ae-46cb-4c2e-a357-734353f7e09a",os_version="Windows",hostname="DESKTOP-S5VJGLH",ip_address="192.168.0.23",infected_file="F:\code\pythonProject\certverify\test\TWOD_Launcher.exe",signature_hash="sha256",serial_number="073637b724547cd847acfd28662a5e5b",thumbprint="281734d4592d1291d27190709cb510b07e22c405d5e0d6119b70e73589f98acf",subject_name="DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA",issuer_name="DigiCert Trusted Root G4",file_created_at="2023-03-03 23:20:42",file_modified_at="2022-04-07 09:14:08"
datetime="2023-03-06 20:33:47",scan_id="033976ae-46cb-4c2e-a357-734353f7e09a",os_version="Windows",hostname="DESKTOP-S5VJGLH",ip_address="192.168.0.23",infected_file="F:\code\pythonProject\certverify\test\VBoxSup.sys",signature_hash="sha256",serial_number="2f451139512f34c8c528b90bca471f767b83c836",thumbprint="3aa166713331d894f240f0931955f123873659053c172c4b22facd5335a81346",subject_name="VirtualBox for Legacy Windows Only Timestamp Kludge 2014",issuer_name="VirtualBox for Legacy Windows Only Timestamp CA",file_created_at="2023-03-03 23:20:43",file_modified_at="2022-10-11 08:11:56"
```
