# A King's Ransom

Look under the hood of some ransomware and determine how to decrypt an important file.

## Background

  A piece of malware ran on one of our systems and encrypted a lot of important files. Most of the affected files were backed up, but one particular file was not. The attacker is demanding an exorbitant amount of money to undo the damage, but while the file is relatively important, it's not worth what is being asked.

## Getting Started

  This challenge was designed to be done on Windows.

  The files required for this challenge are in the [challenge](challenge) directory. [main.zip](challenge/main.zip) contains the malware program. [decrypt.me](challenge/decrypt.me) is the file that needs to be decrypted. 

  The source directory contains the source code for both the main Python script and the DLL used in the challenge. The Python script was built into an executable file with [pyinstaller](https://pyinstaller.readthedocs.io/en/stable/).
  
  PyInstaller Extractor (pyinstxtractor) is a tool that may help you get a better understanding of the malware. You can view and download the `pyinstxtractor` project on [GitHub](https://github.com/extremecoders-re/pyinstxtractor).

## Submission

  There are two tokens for you to retrieve. One is the name of a decryption function contained in the malware. The other is the decrypted content of the `decrypt.me` file.

## Building the DLL

  First, you will need to install [rustup](https://rustup.rs/). This will install the Rust language compiler. However, you will probably need to install additional build tools for your system. On Windows, you will likely need to install [Visual Studio](https://visualstudio.microsoft.com/downloads/) or its command-line build tools.

To test that you have all of the build tools installed, create and build a new Rust project with:
```
cargo new testproj
cd testproj
cargo build
```

If everything is correctly installed, the test project will quickly build and succeed. Once you know that the build tools are installed correctly, change directory to the DLL source (`solution/source/kings_ransom_rslib`)  and `cargo build --release`. This will build the DLL, which will be placed under the source directory at `target/release`. This can replace the pre-built DLL that exists under the main executable source.


## Building the Python exe

  You will need to have Python 3.7 installed, as well as the [pipenv](https://pypi.org/project/pipenv/) tool within your Python environment. Navigate to `solution/source/kings_ransom_pyclient` and `pipenv install --dev` to install all development packages. Then run `pyinstaller main.spec`. This will bundle the main script and the `enc.dll` file.