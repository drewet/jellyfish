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
- Have OpenCL drivers/icds installed (Fun fact: Mac OS X boxes come pre-installed with OpenCL)
- Nvidia or AMD graphics card (intel supports amd's sdk)

Update:
- Compiler errors resolved, testing PoC now

Disclaimer:
Educational purposes only; authors of this project/demonstration are in no way, shape or form responsible for what you may use this
for whether illegal or not.

Heads up:
- Windows GPU Remote Access Tool (RAT) PoC official release @ /WIN_JELLY
