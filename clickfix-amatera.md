# ClickFix Leads to Half-Baked Amatera Stealer

Welcome to my first blog post! I figured an easy target for a first post might be a ClickFix chain since that is all the rage right now. This one turned out kind of interesting because the phishing page and the resulting Amatera payload seem like they are under development or something because they are really janky. In addition to the Amatera stealer payload, this chain drops a .NET executable that configures the users' browsers to proxy traffic through the attacker's server.

Contents:
* [What is ClickFix](#what-is-clickfix)
* [Finding a sample](#finding-a-sample)
* [Analyzing the site](#analyzing-the-site)
* [i4756ms.exe](#i4756msexe)
* [4756ms.exe and Qt6Core.dll](#4756msexe-and-qt6coredll)
* [Amatera stealer](#amatera-stealer-payload)
* [hostUpdatei4756ms.exe](#hostupdatei4756msexe)
* [IOCs](#iocs)

## What is ClickFix?

If you're not familiar, ClickFix is a social engineering attack where users are tricked into running programs or commands to fix a perceived issue with a site or document. A common one these days is a fake CAPTCHA popup asking the user to press the Windows key + R and Ctrl + V in order to prove that the user is not a robot. Secretly, the page has copied a malicious command to the user's clipboard and that key combination will run the command, which typically downloads and executes additional stages of malware.

![A ClickFix fake CAPTCHA](/images/clickfix/typical-clickfix.png)

*A typical ClickFix fake CAPTCHA*

## Finding a sample

I used the Shodan query `http.html:"Win R"` to find pages that might be prompting the user to run the Windows + R method of ClickFix. As expected, there were many results. The first result had a Russian title, which seemed interesting, so I decided to look into that one. 

![Shodan results for ClickFix pages](/images/clickfix/shodan.png)

*Shodan results for potential ClickFix pages*

## Analyzing the site

From the Shodan details, that page was served over HTTP on port 80, so it can be accessed by just visiting the IP address in the browser. The page was completely blank except for a poorly formated reCAPTCHA prompt:

![Fake reCAPTCHA dialog](/images/clickfix/recaptcha.png)

*Fake reCAPTCHA prompt*

Clicking the checkbox in the reCAPTCHA, it displays the typical popup prompting the user to run the command:

![Win + R popup](/images/clickfix/winr-popup.png)

*ClickFix popup*

The malicious command can be found by inspecting the page source in the browser. In this case, it is a PowerShell command to download an archive from a shortened link, use the tar command to extract the contents, and execute a file called `i4756ms.exe`.

![Malicious command in the page source](/images/clickfix/malicious-command.png)

*PowerShell command hiding in the page source*

## i4756ms.exe

This file already existed on VirusTotal and was first submitted in December, 2024.

![VirusTotal history for i4756ms.exe](/images/clickfix/vt-history.png)

*VirusTotal submission history for i4756ms.exe*

Detect It Easy classifies the file as a self-extracting Microsoft Cabinet File. In the resources section of the file there are RUNPROGRAM and POSTRUNPROGRAM entries that dictate files to be run once the archive has been extracted. In this case, `4756ms.exe` will be executed first, then `hostUpdatei4756ms.exe`.

![RUNPROGRAM and POSTRUNPROGRAM resources](/images/clickfix/die-output.png)

*RUNPROGRAM and POSTRUNPROGRAM resources viewed in Detect It Easy*

7-Zip can be used to extract the files from the archive. Inside, there are quite a few DLLs and the two EXEs referenced in the resources. Searching for the files on VirusTotal, `hostUpdatei4756ms.exe`, `Qt6Core.dll`, and `Torchtray.dll` were marked malcious in VirusTotal and `concrt140e.dll` was not found, so these were the next files to look into.

![CAB contents](/images/clickfix/extracted-files.png)

*Extracted files from the CAB*

## 4756ms.exe and Qt6Core.dll

`4756ms.exe` is the first file to execute when running the self-extracting archive. This file is marked benign in VirusTotal, but it imports functions from `Qt6Core.dll`. Since we know from VirusTotal that this DLL is malicious, this must be a case of DLL sideloading. Unfortunately, it imports 400 functions from the DLL, so at first glance it is hard to tell where the malicious functionality may be in the DLL.

![4756ms.exe imports](/images/clickfix/imports.png)

*4756ms.exe imports*

Looking at the strings in `Qt6Core.dll`, there are some references to APIs commonly associated with process injection:

![Suspicious strings](/images/clickfix/process-injection-apis.png)

*Suspicious strings in the DLL*

The code in the DLL looked pretty complex and I spotted what looked like a binary hidden in the .rdata section, so I decided to go the easy route and use a debugger to dump what I presumed to be a second payload injected into a remote process.

![Embedded PE file](/images/clickfix/embedded-pe.png)

*This looks like PE file data*

For this, I loaded `4756ms.exe` into x64dbg and added conditional breakpoints to see what is going on. For these breakpoints, most have a break condition of 0 and log condition of 1 to allow the program to continue executing while logging some details about the target API invocation. The breakpoint at WriteProcessMemory has a break condition of 1 so that I can stop when the payload is ready to be injected into the remote process.

![x64dbg conditional breakpoints](/images/clickfix/x64dbg-bps.png)

*Breakpoints in x64dbg to trace the process injection*

After executing until the WriteProcessMemory breakpoint, the logs show the program allocating a bunch of memory, loading `bcryptprimitives.dll`, creating a process `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe`, and writing to process memory.

![x64dbg log output](/images/clickfix/x64dbg-logs.png)

*The log output from the conditional breakpoints*

Inspecting the address of the buffer in the first WriteProcessMemory call, it looks like the payload has been decrypted:

![PE payload in memory](/images/clickfix/in-mem-pe.png)

*PE file found in memory*

In a very unscientific fashion, I just scrolled down in the dump until it looked like there wasn't any more data and I dumped from the start address to that point.

## Amatera stealer payload

Detect It Easy shows that the payload has a compile time of December, 2024, which tracks with when the archive file was first submitted to VirusTotal.

![Detect It Easy details for the extracted payload](/images/clickfix/die-output-amatera.png)

*Detect It Easy output for the extracted payload*

There is an IP address in the strings, so I looked it up in VirusTotal. A comment for the IP linked it to Amatera stealer, so this gave a lead for analyzing the sample.

![Strings from the payload](/images/clickfix/amatera-strings.png)

*IP address found in the strings*

![VirusTotal comment on the IP address](/images/clickfix/vt-comment.png)

*Helpful comment on VirusTotal*

I found two great reports on Amatera, which I reviewed before continuing analysis:

* [https://www.proofpoint.com/us/blog/threat-insight/amatera-stealer-rebranded-acr-stealer-improved-evasion-sophistication](https://www.proofpoint.com/us/blog/threat-insight/amatera-stealer-rebranded-acr-stealer-improved-evasion-sophistication)
* [https://github.com/VenzoV/MalwareAnalysisReports/blob/main/AmateraStealer/Amatera%20Stealer%20v1.md](https://github.com/VenzoV/MalwareAnalysisReports/blob/main/AmateraStealer/Amatera%20Stealer%20v1.md)

Most of the functionality observed in this sample aligned with the existing reports, but some differences, mainly with the config parsing, lead me to believe that this is an early developmental stage of the stealer.

The program executes these main steps:

1) Resolve Windows APIs

2) Create a mutex with a hardcoded GUID value
   - This value is also used as the auth header when establishing a C2 session and as the RC4 key to decrypt the config

4) Establish session with hardcoded C2 and fetch the config

5) Parse the config (incomplete)

6) Collect and send the following to the C2:
   - System information
   - Telegram, Filezilla, Discord, AnyDesk, Binance, Steam, and Bitcoin wallet information
   - Gecko browser data
   - Chromium browser data

![Amatera main function](/images/clickfix/amatera-main.png)

*The main function*

When establishing a session, the mutex value is reused as the Authorization header in a GET request to `/core/createSession`. The C2 responds with the configuration, which is Base64-decoded and decrypted with RC4 using the mutex value as the key.

Unfortunately, the C2 did not respond to requests when I tried to pull the configuration.

![C2 session function](/images/clickfix/establish-session.png)

*Function to establish a session with the C2*

The C2 responds to the session request with the configuration that includes a session ID and rules for which information the malware will steal. The parsing logic in this sample differs from the reports listed above. While those reports observed JSON-formatted configuration, this sample seems to expect key-value pairs separated by pipes and newlines for each entry, e.g.:
```
session_id|123456
grabber_rules|firefox,chrome,etc.
```
As mentioned before, I was unable to fetch a config from the C2, so I don't actually know what the session_id or grabber_rules values look like. 

Another interesting difference is that the parsing logic seems incomplete. When parsing the config keys, it checks for `session_id` and then it checks for `grabber_rules`, but it doesn't do anything with the result of that check. In VenzoV's writeup linked above, the parsing logic checked for many more config keys.

![Config parsing](/images/clickfix/config-parsing.png)

*Config parsing logic*

When sending information back to the C2, the session ID extracted from the config is used as the Authorization header and the RC4 key to encrypt the data. It is sent in a POST request to `/core/sendPart`.

![Sending data back to the C2](/images/clickfix/send-to-c2.png)

*Function for sending data to the C2*

## hostUpdatei4756ms.exe

Recalling back to the SFX CAB file, there were entries for RUNPROGRAM and POSTRUNPROGRAM. RUNPROGRAM runs the Amatera stealer payload and POSTRUNPROGRAM runs `hostUpdatei4756ms.exe`.

This is a .NET executable that was also called `Proxy.Client.exe` in VirusTotal. I have a handy little parser utility to pull some metadata from .NET samples - [dnparser](https://github.com/kenzobenj/dnparser). That tool provides the following output:

```
-------------------------------------------------------------------------------------
                                       STREAMS

Stream               Size                 RVA                  Physical Address
#~                   0XDA8                0X3908               0X1B08
#Strings             0XE60                0X46B0               0X28B0
#US                  0X112C               0X5510               0X3710
#GUID                0X10                 0X663C               0X483C
#Blob                0X690                0X664C               0X484C
-------------------------------------------------------------------------------------
                                  Assembly Details

Name: Proxy.Client
Version: 1.0.0.0
Version Hex: 0100000000000000
-------------------------------------------------------------------------------------
                                     Module Name

Proxy.Client.exe
-------------------------------------------------------------------------------------
                                        MVID

Hex                                      UUID
fa80f05a2373eb40ab8f3add47600928         5af080fa-7323-40eb-ab8f-3add47600928
-------------------------------------------------------------------------------------
                                     TypeLib ID

1a9d3ae7-a3fc-4606-95b6-6557ffbd5a14
```

The only thing useful in this case is the TypeLib ID, which was linked to several other files in VirusTotal. It may be interesting to look into the relations of those other samples, but I'll save that for another time.

Looking at the sample in DNSpy, it seems there is a certificate resource:

![Certificate stored as a resource](/images/clickfix/cert-resource.png)

*Certificate seen in DNSpy*

The cert has the magic bytes `30 82`, so it is in DER format. The details can be extracted with:

`openssl x509 -in cert -inform der -text -noout`

![Certificate details](/images/clickfix/cert-output.png)

*Certificate details*

The main program loads the certificate into the certificate store, runs the ChromeModifier and GeckoModifier classes, and deletes itself.

![Main function of the proxy app](/images/clickfix/proxy-main.png)

*Main function*

The modifier classes search for LNK files for their target browsers and modify them to include proxy server and user agent settings when launching. This will proxy all browser traffic through the attacker C2 when users launch their browsers through the LNK files.

![Chromium LNK modification](/images/clickfix/chrome-modifier.png)

*Chromium LNK modification*

The user agent is changed to include what seems to be a campaign ID (Bi) and an infection ID (Id).

![User agent generation](/images/clickfix/user-agent-proxy.png)

*Generating the user agent*

The C2 address and port for the proxy is hardcoded in the config:

![Proxy config](/images/clickfix/proxy-config.png)

*Proxy config*

## Thank you!

If you made it this far, thank you for reading! You may be wondering about the `Torchtray.dll` file I mentioned earlier that was flagged as malicious in VirusTotal. I haven't analyzed it yet, but maybe I will later and update this blog with the details. This was a quick weekend project and I ran out of time. ¯\\_(ツ)_/¯

## IOCs

Phishing page:
* `209.126.9[.]234`
* `vmi1130338[.]contaboserver[.]net`

Malicious archive URL:
* `hxxps[://]cutt[.]ly/jeBlj6HK`

Proxy server:
* `141.105.130[.]106:37121`

Proxy private key:
* `SHA1 Fingerprint=BF:C5:FB:F0:42:F2:5A:0B:CA:F8:B7:C2:54:4D:A2:03:DF:89:8B:12`
* `SHA256 Fingerprint=0F:E2:0C:CF:D5:A7:A8:69:E0:E9:1E:C3:32:22:71:57:21:1A:98:46:88:6A:DE:D3:E9:3A:E3:E9:22:15:B4:5A`

Amatera C2:
* `45.89.196[.]115`

Amatera mutex:
* `3ceee625-5df7-4df1-9884-bc7a8a2fe79b`

SHA256 file hashes:
* i4756ms.zip - `469e9a61727ff1487805987e7ab4c40760ecf551b9e2f6b0a2201308849299d3`
* i4756ms.exe - `436dd0245602a0a9d8b346aa1060784fed3a43aca303a2e7986a0d1121114493`
* hostUpdatei4756ms.exe - `13e97684836d74b193343b73d684671aded05a9e3ac0dc21d534dadad359e754`
* Qt6Core.dll - `6f273bea53117865c913481b101dbca3f5abc5effd1800a6f4640f93043c9d4f`
* Torchtray.dll - `5599784893e50c87788e74d8b56120fc473e665b1a7f2c28e30b744afec13069`
* Amatera payload - `7b3494f34ce8ba4aef70c25831facf5e95bef885ed89ad1c8efc954f15126b8a`