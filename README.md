# Jomungand

Shellcode Loader with memory evasion by @DallasFR

# How it's work ?

I use HWBP to hook VirtualAlloc, Sleep and LoadLibraryA. Why i hook this function ?

- VirtualAlloc : CobaltStrike & Meterprter is reflective dll as shellcode, with the VirtualAlloc hook we can obtain the real addresse of shellcode in memory

- Sleep : I hook sleep to use KrakenMask and encrypt all the content of shellcode in memory during sleep

- LoadLibraryA : I redirect to LdrLoadDll with ret addr spoofing. Some edr can detect malicious LoadLibraryA if the origin of call is not backed on RX present on disk



All NT API call was made with indirect syscall and i spoof the ret addr.


When the first sleep was called, i free the virtual memory alloced to read the shellcode from file.

![alt text](https://raw.githubusercontent.com/RtlDallas/Jomungand-/main/img/ldr.png)

# Memory scanner

- PE-Sieve : Detect nothing
- Moneta : 1 Detection, the exe image is an unsigned module
- Hunt sleeping beacons : Detect nothing
- Patriot : Detect nothing

![alt text](https://raw.githubusercontent.com/RtlDallas/Jomungand-/main/img/scanner.png)
