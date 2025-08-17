# nubbscan
> [!CAUTION]
> Port scanning should only be done in contained, lab environments or in penetration tests with written authorization by a client. Running port scanners may trigger NDR (Network Detection and Response) systems and flag you as a malicious actor.

My own multithreaded TCP/UDP port scanner written in Python for enumeration.

# agenda
Renamed to nubbscan cuz chroma suggested such, may be rewritten in C# or Go or some other language for speed

Domain resolution is now possible thanks to the socket library being goated. Also OS detection, and added 8080 as an extra port to scan for. Overall the scanner is basically complete with how many features there are imo.

# dependencies
No external packages are needed for running this scanner, according to `pipreqs`. DM me on Discord @ nubbieeee if you have questions tho.
