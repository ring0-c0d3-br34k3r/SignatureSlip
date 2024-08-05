# SignatureSlip

This repository contains code that allows you to disable Driver Signature Enforcement (DSE) in Windows 10 and 11. 
![image](https://github.com/user-attachments/assets/c8717c93-a679-410b-a32c-b6992806eb46)

## Overview

Driver Signature Enforcement is a security feature in Windows that requires all drivers to be signed by Microsoft with a digital signature before they can be installed and loaded into the Windows kernel. This feature enhances system stability and security by ensuring that only trusted and verified drivers are allowed to run on the system.

However, there may be scenarios where you need to install unsigned or unverified drivers, such as when using drivers from unofficial sources or when developing custom drivers. The code in this repository provides a way to disable the Driver Signature Enforcement feature, allowing you to install and load unsigned drivers on your system.

## Features

- Disables Driver Signature Enforcement in Windows 10 and 11.
- Includes shellcode payloads for both Windows 10 and 11.
- Allows the installation and loading of unsigned drivers.
- Can be used by security researchers, Red/blue teams...

## Usage

1. Ensure that you understand the implications of disabling Driver Signature Enforcement and the potential security risks involved.
2. Compile the code using a C/C++ compiler that supports Windows development.
3. Run the compiled executable with administrative privileges.
4. The program will load a vulnerable driver and manipulate kernel-level variables to disable the Driver Signature Enforcement feature.
5. After the modification, you will be able to install and load unsigned drivers on your system.
6. Use caution when installing unsigned drivers and ensure they come from trusted sources.

## Disclaimer

This code is provided for educational and research purposes only. Disabling Driver Signature Enforcement can introduce security risks to your system. Use this code at your own risk and ensure you understand the implications before running it on your machine.

## Contact

If you have any questions or suggestions regarding this code, feel free to reach out to me :

- Name: Panji
- Telegram: [@I0p17j8](https://t.me/I0p17j8)

## License

This code is licensed under the [MIT License](https://opensource.org/licenses/MIT). Feel free to modify, distribute, and use it in accordance with the license terms.
