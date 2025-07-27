# ClickFix Leads to Half-Baked Amatera Stealer

Welcome to my first blog post! I figured an easy target for a first post might be a ClickFix chain since that is all the rage right now. This one turned out kind of interesting because the phishing page and the resulting payload seem like they are under development or something because the are really janky.

## What is ClickFix?

If you're not familiar, ClickFix is a social engineering attack where users are tricked into running programs or commands to fix a perceived issue with a site or document. A common one these days is a fake CAPTCHA popup asking the user to use the Windows key + R to run a command in order to prove that the user is not a robot. Secretly, the page has copied a malicious command to the user's clipboard, so they will download and execute malware when running the command.

![A CLickFix fake CAPTCHA](/images/clickfix/typical-clickfix.png)

*A typical ClickFix fake CAPTCHA*

