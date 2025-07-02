# sawyer
> [!CAUTION]
> Port scanning should only be done in contained, lab environments or in penetration tests with written authorization within your rules of engagement. Running port scanners may trigger NDR (Network Detection and Response) systems and flag you as a malicious actor which will get you in trouble!

My own multithreaded TCP/UDP port scanner written in Python for enumeration.

# agenda
Appears to work a bit thus far. Still needs some testing in lab environments to see if the scanning actually works lol. It runs really fast which is nice.

I plan to add in a feature to specify extra ports to scan, so we can say check for WinRM on port 5985 without having to set the range all the way up there.
