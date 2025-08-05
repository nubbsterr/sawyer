# sawyer
> [!CAUTION]
> Port scanning should only be done in contained, lab environments or in penetration tests with written authorization within your rules of engagement. Running port scanners may trigger NDR (Network Detection and Response) systems, NIDS/NIPS (Network Intrusion Detection/Prevemtion System), etc., and flag you as a malicious actor and make a SOC team or MSSP hate their lives cuz they have another incident to handle potentially.

My own multithreaded TCP/UDP port scanner written in Python for enumeration.

# agenda
Actually works, at least when scanning against localhost, it shows ssh and smtp open lol. Also added coloured terminal output using ANSI escape codes, so no dependencies needed, which is great.

Next thing to try is getting more telemetry on the scanned machine, like greater service information and OS information.

# dependencies
No external packages are needed for running this scanner, according to `pipreqs`. DM me on Discord @ nubbieeee if you have questions tho.
