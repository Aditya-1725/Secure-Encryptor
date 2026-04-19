#  Secure Encryption Tool  

A Python-based encryption tool developed during my Cyber Security internship.  
It uses AES-128 (CBC mode) with PBKDF2 for secure text and file encryption.  

---

##  Features  
- Encrypt & Decrypt text  
- Encrypt & Decrypt files  
- Password-based key generation  
- Secure (AES-128 + Salt + IV)  
- Simple GUI  

---

##  Setup  

git clone https://github.com/Aditya-1725/Secure-Encryptor.git
cd Secure Encryptor  

python -m venv venv  
venv\Scripts\activate   (Windows)  

pip install cryptography  

python app.py   
