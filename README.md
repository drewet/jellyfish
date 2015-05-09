Jellyfish is a Linux based userland gpu rootkit proof of concept project utilizing the LD_PRELOAD technique from Jynx (CPU), as
well as the OpenCL API developed by Khronos group (GPU). Code currently supports AMD and NVIDIA graphics cards. However, the
AMDAPPSDK does support Intel as well. 

Advantages of gpu stored memory:
- No gpu malware analysis tools available on web
- Can snoop on cpu host memory via DMA
- Gpu can be used for fast/swift mathematical calculations like xor'ing or parsing
- Stubs
- Malicious memory may be retained across warm reboots. (Did more conductive research on the theory of malicious memory still being in gpu after shutdown)

Requirements for use:
- Have OpenCL drivers/icds installed
- Nvidia or AMD graphics card (intel supports amd's sdk)
- Change line 103 in rootkit/kit.c to server ip you want to monitor gpu client from

Stay tuned for more features:
- client listener; let buffers stay stored in gpu until you send magic packet from server

Disclaimer:
Educational purposes only; authors of this project/demonstration are in no way, shape or form responsible for what you may use this
for whether illegal or not.

PLEASE READ:
- For some arbitrary reason this project as well as Demon, has been getting a decent amount of attention. That being said, we just
want to notify everyone reading this that jellyfish is not complete nor has it even reached the expectations we wanted it to yet.
We're still circling around ideas and pseudo code upon what we think is cool, so apologies to anyone disappointed that they still have
a buggy still-in-beta application. Our goal was to make everyone AWARE that gpu based malware IS REAL; and obviously, telling
from what's been publicized, we succeeded.

Also, to an individual that commented on an arstechnica article about us. Yes, we're very early in development for both projects,
so sit tight and enjoy the show.

Heads up:
- New and upcoming Windows GPU rootkit PoC on the way @ /WIN_JELLY. We have some source available for anyone interested.