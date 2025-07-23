# sawyer
> [!CAUTION]
> Port scanning should only be done in contained, lab environments or in penetration tests with written authorization within your rules of engagement. Running port scanners may trigger NDR (Network Detection and Response) systems and flag you as a malicious actor and make the blue teamers hate their day.

My own multithreaded TCP/UDP port scanner written in Python for enumeration.

# agenda
Appears to work a bit thus far. Still needs some testing in lab environments to see if the scanning actually works lol. It runs really fast which is nice. I found that Futures runs waaaay faster than Threading, but I'm like certain it's cuz I was missing sumn w/ my scripting logic.

# dependencies
Make sure to have all needed dependencies. I used `pipreqs` to create the `requirements.txt` list but if anything is missing please DM me on Discord @ nubbieeee.
