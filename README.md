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


## Limitations of the tool
1. The Code Signing Certificate Scanner cannot guarantee that all files identified as suspicious are necessarily malicious. It is possible for files to be falsely identified as suspicious, or for malicious files to go undetected by the scanner.

2. The scanner only targets code signing certificates that have been identified as malicious by the public community. This includes certificates extracted by malware analysis tools and services, and other public sources. There are many unverified malware signing certificates, and it is not possible to obtain the entire malware signing certificate; the tool can only detect some of them. For additional detection, you have to extract the certificate's serial number and fingerprint information yourself and add it to the signatures.


3. The scope of this tool does not include the extraction of code signing information for special rootkits that have already preempted and operated under the kernel, such as FileLess bootkits, or hidden files hidden by low-end technology. In other words, if you run this tool, it will be executed at the user level. Similar functions at the kernel level are more accurate with antirootkit or EDR. Please keep this in mind and focus on the ideas and principles... To implement the principle that is appropriate for the purpose of this tool, you need to development a driver(sys) and run it into the kernel with NT SYSTEM privileges.

4. Nevertheless, if you want to run this tool in the event of a Windows system intrusion incident, and your purpose is sys files, boot into safe mode or another boot option that does not load the default driver(sys) files of the Windows system before running the tool. I think this can be a little more helpful.

5. Alternatively, mount the Windows system disk to the Linux and run the tool in the Linux environment. I think this could yield better results.


## Features
- File inspection based on leaked, untrusted certificate
- Scanning include subdirectories
- Define directories not to scanning
- MultiProcessing Jobs
- Whitelisting based on the certificate subject (e.g., Microsoft Subject certificates are exempt from detection)
- Skip the inspection of unsigned files for fast scan. 
- Easy to attach scan_logs to the SIEM (e.g Splunk)
- Easy to Handle and changeable code/function structure 


## And...
- Let me know if there are any changes required or additional features need it.
- and press the "stars" if it helps. then it will continue to improvement.


## v1.0.0


## Preview


## Scan result_log

```

```
