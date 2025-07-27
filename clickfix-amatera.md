# ClickFix Leads to Half-Baked Amatera Stealer

Welcome to my first blog post! I figured an easy target for a first post might be a ClickFix chain since that is all the rage right now. This one turned out kind of interesting because the phishing page and the resulting payload seem like they are under development or something because the are really janky.

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







