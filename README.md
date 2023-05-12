# SCRYPT: An Introduction to Shellcode Encoding

## Introduction
SCRYPT is a simple shellcode encoder that applies several encoding techniques to obfuscate a given shellcode file. This encoded shellcode can be used for both legitimate and malicious purposes, such as exploiting system vulnerabilities or executing arbitrary code. 

## Compiling
To compile the program, use the following command:
```bash
gcc -o scrypt scrypt.c
```

## Usage
To use this program, run the following command:
```
./scrypt shellcode.bin
```
where `shellcode.bin` is the name of the binary file containing the shellcode to be encoded.

After running the program, the encoded shellcode will be written to your terminal in C-style format. You can copy and paste this encoded shellcode into your own C program and use it for your own purposes. (After having decoded it, of course! (I will be adding a decoder program soon.))
## Encoding Techniques
SCRYPT uses the following encoding techniques to obfuscate the shellcode:
* **XOR Encoding**: SCRYPT generates a random XOR key of the same size as the shellcode and applies XOR operation to each byte of the shellcode with a corresponding byte of the XOR key. This technique can make it harder for antivirus software to detect the shellcode.
* **ROT Encoding**: SCRYPT generates a random number between 1 and 8 and performs a rotation (shift) operation on each byte of the shellcode by that amount. This further obfuscates the shellcode.
* **DEC Encoding**: SCRYPT subtracts a random value from each bit of the shellcode to produce a decimal representation of the original value. This encoding technique is also known as decimal encoding or decimalization.
* **Byte Insertion Encoding**: This technique involves inserting a random byte after each byte in the shellcode. In SCRYPT, a new buffer is created for the encoded shellcode, and a random byte is inserted after every other byte.

## Shellcode Payloads
A shellcode is a small piece of code that is designed to perform a specific task or execute arbitrary code when injected into a vulnerable process or system. Shellcode payloads can be used for both legitimate and malicious purposes, depending on the context and intent of the user.

## Program Limitations and Possible Improvements
SCRYPT is a basic shellcode encoder and has several limitations. For example, it uses a simple random number generator to generate the XOR key, which is not cryptographically secure and can be easily predicted or brute-forced. The program could benefit from more advanced encoding techniques and algorithms to improve the obfuscation of the shellcode.

To improve the program, one could consider using more robust random number generators, implementing more complex encoding techniques such as polymorphic or metamorphic encoding, or adding anti-analysis features to detect and thwart reverse engineering attempts by security researchers or antivirus software.

## Screenshots
Two screenshots of SCRYPT in action are provided below:

![Screenshot 1](./media/screenshot1.png "Screenshot 1")

![Screenshot 2](./media/screenshot2.png "Screenshot 2")

## Conclusion
SCRYPT provides an introduction to shellcode encoding and demonstrates some basic encoding techniques that can be used to obfuscate shellcode payloads. However, it is important to note that the use of shellcode for malicious purposes is illegal and can result in severe consequences. This program should only be used for educational or research purposes, and not for any malicious activities.