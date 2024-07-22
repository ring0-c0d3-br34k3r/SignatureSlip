# SignatureSlip
This code is a driver loading exploit that bypasses the Windows OS's driver signing time validity checks.



==> "SignatureSlip : A Windows Driver Loading Exploit"

- Overview

SignatureSlip is a Windows driver loading exploit that empowers users to bypass the digital certificate validation checks in the CertVerifyTimeValidity function, allowing them to load unsigned drivers on Windows systems. This tool is designed for educational purposes only and should not be used for malicious activities.

- Features :

~ Bypasses Digital Certificate Validation : WinDriverForce bypasses the digital certificate validation checks in the CertVerifyTimeValidity function, allowing users to load unsigned drivers on Windows systems.

~ Customizable Driver Loading : The tool provides a user-friendly interface for selecting and loading unsigned drivers.

~ Anti-Debugging Techniques : WinDriverForce includes anti-debugging techniques to evade detection by debuggers and security software.

~ Cross-Platform Compatibility : The tool supports multiple Windows versions, from Windows 7 to the latest releases.


- Getting Started :

1 - Clone the repository : "git clone https://github.com/0xp17j8/SignatureSlip.git"

2 - Build the project : cl /EHsc /I "C:\\Detours\\include" SignatureSlip.c /link /LIBPATH:"C:\Detours\lib.ARM\detours.lib" C:\Detours\lib.ARM\detours.lib

3 - Run the exploit : ./SignatureSlip.exe

4 - Follow the prompts to select and load an unsigned driver


Prerequisites :

Windows 7 or later until 11
Visual Studio 2019 or later (for building)
A Windows driver (unsigned)


- Notes :

Use this tool responsibly and at your own risk. Malfunctioning drivers can cause system instability or data corruption.
It is recommended to test this tool in a controlled environment before using it on a production system.
Do not use this tool for malicious activities.
Acknowledgments

The development of WinDriverForce was inspired by the Detours library and the Windows driver signing policy.

- License :

This project is licensed under the MIT License.

- Author

[Zakariae Tafjouti]
[panji]
