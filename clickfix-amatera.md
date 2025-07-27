# ClickFix Leads to Half-Baked Amatera Stealer

Welcome to my first blog post! I figured an easy target for a first post might be a ClickFix chain since that is all the rage right now. This one turned out kind of interesting because the phishing page and the resulting payload seem like they are under development or something because the are really janky.

Contents:
* [What is ClickFix](#what-is-clickfix)
* [Finding a sample](#finding-a-sample)
* [Analyzing the site](#analyzing-the-site)
* [i4756ms.exe](#i4756msexe)
* [4756ms.exe and Qt6Core.dll](#4756msexe-and-qt6coredll)
* [Amatera stealer](#amatera-stealer-payload)

## What is ClickFix?

If you're not familiar, ClickFix is a social engineering attack where users are tricked into running programs or commands to fix a perceived issue with a site or document. A common one these days is a fake CAPTCHA popup asking the user to press the Windows key + R and Ctrl + V in order to prove that the user is not a robot. Secretly, the page has copied a malicious command to the user's clipboard, so that key combination will run the command, which typically downloads and executes additional stages of malware.

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

In a very unscientific fashion, I just scrolled down in the dumpm until it looked like there wasn't anymore data and I dumped from the start address to that point.

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

* https://www.proofpoint.com/us/blog/threat-insight/amatera-stealer-rebranded-acr-stealer-improved-evasion-sophistication
* https://github.com/VenzoV/MalwareAnalysisReports/blob/main/AmateraStealer/Amatera%20Stealer%20v1.md


