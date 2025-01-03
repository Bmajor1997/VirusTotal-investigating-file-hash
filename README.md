# VirusTotal-investigating-file-hash Project

<h2>Directions:</h2>
In this activity, you'll analyze an artifact using VirusTotal and capture details about its related indicators of compromise using the Pyramid of Pain.  
<h2>Scenerio<img width="919" alt="Screen Shot 2025-01-03 at 2 09 43 PM" src="https://github.com/user-attachments/assets/06ffe4a0-4af7-4a29-9d2c-bc5f61599c10" />
<h2>Steps</h2>
The following information contains details about the alert that will help you complete this activity. The details include a file hash and a timeline of the event. Keep these details for reference as you proceed to the next steps.
<h2></h2>
  
Step 1) SHA256 file hash: 54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b

Here is a timeline of the events leading up to this alert:

1:11 p.m.: An employee receives an email containing a file attachment.

1:13 p.m.: The employee successfully downloads and opens the file.

1:15 p.m.: Multiple unauthorized executable files are created on the employee's computer.

1:20 p.m.: An intrusion detection system detects the executable files and sends out an alert to the SOC.

Step 2) Once you've retrieved VirusTotal's report on the file hash, take some time to examine the report details. You can start by exploring the following tabs:
<img width="1124" alt="Screen Shot 2025-01-03 at 2 34 40 PM" src="https://github.com/user-attachments/assets/25980f32-3fe7-4214-ae91-62affbed0655" />

Detection: This tab provides a list of third-party security vendors and their detection verdicts on an artifact. Detection verdicts include: malicious, suspicious, unsafe, and others. Notice how many security vendors have reported this hash as malicious and how many have not.
<img width="1121" alt="Screen Shot 2025-01-03 at 2 36 03 PM" src="https://github.com/user-attachments/assets/54b64942-d250-4f18-ad57-3d11729a3a0b" />

Details: This tab provides additional information extracted from a static analysis of the IoC. Notice the additional hashes associated with this malware like MD5, SHA-1, and more. 
<img width="1121" alt="Screen Shot 2025-01-03 at 2 37 50 PM" src="https://github.com/user-attachments/assets/cefdcd32-aec2-4e02-80b5-071e195a18d7" />

Relations: This tab contains information about the network connections this malware has made with URLs, domain names, and IP addresses. The Detections column indicates how many vendors have flagged the URL or IP address as malicious.
<img width="1067" alt="Screen Shot 2025-01-03 at 2 39 13 PM" src="https://github.com/user-attachments/assets/8a523cf2-5473-4e0d-bb8e-d346d5abfc63" />

Behavior: This tab contains information related to the observed activity and behaviors of an artifact after executing it in a controlled environment, such as a sandboxed environment. A sandboxed environment is an isolated environment that allows a file to be executed and observed by analysts and researchers. Information about the malware's behavioral patterns is provided through sandbox reports. Sandbox reports include information about the specific actions the file takes when it's executed in a sandboxed environment, such as registry and file system actions, processes, and more. Notice the different types of tactics and techniques used by this malware and the files it created.
<img width="1095" alt="Screen Shot 2025-01-03 at 2 41 51 PM" src="https://github.com/user-attachments/assets/e743038c-ce0a-41f8-90b7-87f9bff10850" />

Step 3) Review the VirusTotal report to determine whether the file is malicious. The following sections will be helpful to review before making this determination:

The Vendors' ratio is the metric widget displayed at the top of the report. This number represents how many security vendors have flagged the file as malicious over all. A file with a high number of vendor flags is more likely to be malicious.

The Community Score is based on the collective inputs of the VirusTotal community. The community score is located below the vendor's ratio and can be displayed by hovering your cursor over the red X. A file with a negative community score is more likely to be malicious.

Under the Detection tab, the Security vendors' analysis section provides a list of detections for this file made by security vendors, like antivirus tools. Vendors who have not identified the file as malicious are marked with a checkmark. Vendors who have flagged the file as malicious are marked with an exclamation mark. Files that are flagged as malicious might also include the name of the malware that was detected and other additional details about the file. This section provides insights into a file's potential maliciousness.

Step 4) Review these three sections to determine if there is a consistent assessment of the file's potential maliciousness such as: a high vendors' ratio, a negative community score, and malware detections in the security vendors' analysis section. 

In the first slide of your Pyramid of Pain template, indicate whether this file is malicious. Then, explain your reasoning based on your findings.

<img width="755" alt="Screen Shot 2025-01-03 at 3 02 44 PM" src="https://github.com/user-attachments/assets/58eccb80-0f19-4d09-b64a-c1d6c669bd12" />

Note: The Vendors' ratio is based on security vendors' detections and vendors might not always detect malicious files. The Community Score is based on the opinions and insights from the VirusTotal community. If a file's scores are low, it doesn't necessarily mean that the file is safe. It is recommended to use multiple sources of information when evaluating files.

After you've explored the sections in the VirusTotal report, you will uncover additional IoCs that are associated with the file according to the VirusTotal report.

Step 5) Identify three indicators of compromise (IoCs) that are associated with this file hash using the tabs in the VirusTotal report. Then, enter the IoCs into their respective sections in the Pyramid of Pain template.

Indicators of compromise are valuable sources of information for security professionals because they are used to identify malicious activity. You can choose to identify any three of the six types of IoCs found in the Pyramid of Pain: 

Hash value: Hashes convert information into a unique value that can't be decrypted. Hashes are often used as unique references to files involved in an intrusion. In this activity, you used a SHA256 hash as the artifact for this investigation. Find another hash that's used to identify this malware and enter it beside the Hash values section in the Pyramid of Pain template. You can use the Details tab to help you identify other hashes.

IP address: Find an IP address that this malware contacted and enter it beside the IP addresses section in the Pyramid of Pain template. You can locate IP addresses in the Relations tab under the Contacted IP addresses section or in the Behavior tab under the IP Traffic section.

Domain name: Find a domain name that this malware contacted and enter it beside the Domain names section in the Pyramid of Pain template. You can find domain name information under the Relations tab. You might encounter benign domain names. Use the Detections column to identify domain names that have been reported as malicious.

Network artifact/host artifact: Malware can create network-related or host-related artifacts on an infected system. Find a network-related or host-related artifact that this malware created and enter it beside the Network/host artifacts section in the Pyramid of Pain template. You can find this information from the sandbox reports under the Behavior tab or from the Relations tab.

Tools: Attackers can use tools to achieve their goal. Try to find out if this malware has used any tool. Then, enter it beside the Tools section in the Pyramid of Pain template.

Tactics, techniques, and procedures (TTPs): TTPs describe the behavior of an attacker. Using the sandbox reports from the Behavior tab, find the list of tactics and techniques used by this malware as identified by MITRE ATT&CK® and enter it beside the TTPs section in the Pyramid of Pain template. 
<img width="1017" alt="Screen Shot 2025-01-03 at 3 38 32 PM" src="https://github.com/user-attachments/assets/514fabcf-90df-415c-bf2b-cce7c6e5b719" />

<h2>Incident handlers journal</h2>
<img width="646" alt="Screen Shot 2025-01-03 at 3 59 57 PM" src="https://github.com/user-attachments/assets/3d824f4e-a647-491f-8303-d219075113aa" />
