# My Stego
A Python-based program used for Steganography, Text Encryption/Decryption, Watermarking.

## Features
- Hide messages in images using steganography
- Encrypt/decrypt messages with AES, DES, or Blowfish
- Add/remove watermarks from images
- User-friendly GUI

## Installation
1. Clone the repository
2. Install requirements: check requirements.txt
3. Run: `python main.py`

## Directories
MyStego/

├── data_encryption.py        
├── image_steganography.py      
├── watermarking.py         
├── gui.py               
├── main.py              
├── README.md             
└── requirements.txt    

## Usage
#### Steganography
In Embed tab, select an image from your device, then enter messages and security key to process.
In Unembed tab, select the image with hidden messages, then enter the security key to process. The process will take roughly 20-30 seconds to complete. 

#### Messages encryption and decryption
In Encrypt tab, enter the messages and the security key to process.
In Decrypt tab, enter the encrypted text and the security key to decrypt.

#### Watermarking
In Watermark tab, choose an image from your device for watermarking, enter the text which will be marked into the image.

#### Settings
It is able to change the night/light theme in the settings.
It is able to choose the cryptography algorithms in the settings.

**Attention:**
In the steganography, except the situation the length of text excess the capacity of the image, the data should follow these requirements:
- In AES algorithm, the entered data should not excess 16 bytes (128 bits) length.
- In Blowfish algorithm, the entered data should be more than 8 bytes (64 bits) length.
