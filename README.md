# Applied Cryptography

### Academic Year: 2024/25

### Grade: 15.9

## Project 1 - Shuffled AES (S-AES)

The S-AES (Shuffled AES) is a modified version of AES encryption. It introduces an additional 128-bit key, the shuffle key (SK), which influences the encryption process. Like AES, S-AES follows a series of encryption rounds, but with a key difference: one of the initial 9 rounds is altered based on SK. Specifically, SK is used to pseudo-randomly select which of these rounds will be modified.

The modified round operates as follows:
- In the AddRoundKey() step, the SK is used to rotate the bytes of the Round Key used in this round.
- The S-Box used in the SubBytes() step is a shuffled variant of the original S-Box wich depends on the SK. 

---
### Python Implementation

The program operates with the normal AES if no SK is provided.

---
To encrypt something, use:
```shell
echo -n "some_plain" | python3 encrypt.py <key> [skey]
```

To decrypt something, use:
```shell
echo -n "some_cipher" | python3 decrypt.py <key> [skey]
```

---
### SAES-NI Implementation

This program uses AES-NI Intel assembly instructions and only works for SAES.

Encrypt and decrypt operations are carried out in the same programme, all at once.

---

To compile the program, you may use the makefile provided:
```shell
cd AES-NI
make
```

To run the program, use:
```shell
echo -n "some_plain" | ./ecb_exe <key> <skey>
```

---

To test the relative performance between S-AES and AES implementations (will take long), run (in root directory):
```shell
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt

chmod +x speed.sh
./speed.sh > time/best_times_100k_runs.txt
```

#### Project done by [@jnluis](https://github.com/jnluis) and [@ricardoquintaneiro](https://github.com/ricardoquintaneiro)