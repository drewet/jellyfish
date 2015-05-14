Jellyfish is a Linux based userland gpu rootkit proof of concept project utilizing the LD_PRELOAD technique from Jynx (CPU), as
well as the OpenCL API developed by Khronos group (GPU). Code currently supports AMD and NVIDIA graphics cards. However, the
AMDAPPSDK does support Intel as well. 

Some advantages of gpu stored memory:
- No gpu malware analysis tools available on web
- Can snoop on cpu host memory via DMA
- Gpu can be used for fast/swift mathematical calculations like xor'ing or parsing
- Stub/signature generation
- Malicious memory may be retained across warm reboots. (Did more conductive research on the theory of malicious memory still being in gpu after shutdown)

Requirements for use:
- Have OpenCL drivers/icds installed (Fun fact: Mac OS X boxes come pre-installed with OpenCL)
- Nvidia or AMD graphics card (intel supports amd's sdk)

Features (more features soon):
- client listener, record data to gpu and send magic packet when ready to dump

Heads up:
- Windows GPU Remote Access Tool (RAT) PoC official release @ /WIN_JELLY
- Working on PoC for Mac OS X @ /MAC_JELLY

Disclaimer:
- Educational purposes only; authors of this project/demonstration are in no way, shape or form responsible for what you may use this
for whether illegal or not.
