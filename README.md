# RotAES
Implementation of RotAES algorithm, which is a new variation of AES cipher. In this algorithm, Mix Column action is replaced with Rotate 90 Degrees Clockwise.

Formal Definition of 𝑅𝑜𝑡𝐴𝐸𝑆:
𝑅𝑜𝑡𝐴𝐸𝑆 is a single-round implementation of AES that is defined as follows:
-  **𝑅𝑜𝑡𝐴𝐸𝑆(𝑀)** = 𝐴𝑑𝑑𝑅𝑜𝑢𝑛𝑑𝐾𝑒𝑦(𝑅𝑜𝑡𝑎𝑡𝑒(𝑆ℎ𝑖𝑓𝑡𝑅𝑜𝑤𝑠(𝑆𝑢𝑏𝐵𝑦𝑡𝑒𝑠(𝑀))), 𝑘) = C
-  **(𝑅𝑜𝑡𝐴𝐸𝑆)<sup>-1</sup>(𝐶)** = 𝑆𝑢𝑏𝐵𝑦𝑡𝑒𝑠<sup>-1</sup>(Sℎ𝑖𝑓𝑡𝑅𝑜𝑤𝑠<sup>-1</sup>(𝑅𝑜𝑡𝑎𝑡𝑒<sup>-1</sup>(A𝑑𝑑𝑅𝑜𝑢𝑛𝑑𝐾𝑒𝑦(𝐶, 𝑘)))) = 𝑀

The encryotion and decription algorithm itself is two keys and two sessions are used of the above algorithm:
- **Double 𝑅𝑜𝑡𝐴𝐸𝑆 Encryption:**
𝐶 = 𝑅𝑜𝑡𝐴𝐸𝑆(𝑅𝑜𝑡𝐴𝐸𝑆(𝑀, 𝑘1) , 𝑘2)
- **Double 𝑅𝑜𝑡𝐴𝐸𝑆 Decryption:**
𝑀 = 𝑅𝑜𝑡𝐴𝐸𝑆
<sup>-1</sup>
(𝑅𝑜𝑡𝐴𝐸𝑆
<sup>-1</sup>
(𝐶, 𝑘2) , 𝑘1)

Using the algorithm:
- python aes.py –e message_path key_path output_path:
  - message_path: The location of the file where the text we want to encrypt is written
  - key_path: The location of the file where the two keys are written, should be concatenated as one
  - out_puth_pathThe location of the file to which you need to write the encryption of the text
- python aes.py –d cipher_path key_path output_path
  - cipher_path: The location of the file where the encrypted text we want to decrypt is written
  - key_path: The location of the file where the two keys are written, when they are concatenated as one
  - output_path: The location of the file to which you need to write the decoding of the text


