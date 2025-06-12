# sawyer
> [!CAUTION]
> Port scanning should only be done in contained, lab environments or in penetration tests with written authorization within your rules of engagement. Running port scanners may trigger NDR (Network Detection and Response) systems and flag you as a malicious actor which will get you in trouble!

My own multithreaded (perchance) TCP/UDP (perchance) port scanner written in Python for enumeration.

# agenda
The script is actually done and just needs testing right now. Only issue is that I can't run it on localhost for some reason; nmap shows my ports are in an ignored state, which I have never seen before. Regardless, I'll test `sawyer` in a VM or HTB lab and see how it goes! 

Next steps are to add a ping scan functionality and the ability to do only TCP or only UDP scans at once, etc. QOL changes really.
