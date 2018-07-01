from typing import List

import os, sys
import random, getpass
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

__version__ = "1.0.0"
_encrExtension = ".encr"

def encrypt(key: bytes, filename: str) -> None:
    """encrypts a file"""
    chunksize = 64*1024
    outputFile = filename + _encrExtension
    filesize = str(os.path.getsize(filename)).zfill(16).encode("utf-8")

    IV = os.urandom(16)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, 'rb') as infile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize)
            outfile.write(IV)
            
            while True:
                chunk = infile.read(chunksize)
                
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))
    return None


def decrypt(key: bytes, filename:str) -> None:
    """decrypts a file"""
    chunksize = 64*1024
    outputFile = filename[:-5]
    
    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outputFile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)
    return None


def getKey(password: bytes) -> bytes:
    """generates a key given password"""
    hasher = SHA256.new(password)
    return hasher.digest()

def getPassword() -> bytes:
    """fetches password without echoing"""
    password = getpass.getpass()
    reEnterPassword = getpass.getpass("reenter password: ")
    if (password != reEnterPassword):
        print("\nPasswords don't match!\n")
        raise ValueError()
    return password.encode("utf-8")

def getAllFiles() -> List[str]:
    """fetches all files in subdirectories"""
    filePaths = []
    for root, _, files in os.walk(os.getcwd()):
        for name in files:
            filePaths.append(os.path.join(root, name))

    return filePaths

def updateGitIgnore() -> None:
    """updates .gitignore so we don't track unencrypted files"""
    message = f"""
# automatically added by {__file__}
*
!*{_encrExtension}
!*.yaml
!{__file__}
"""
    gitPath = os.path.join(os.getcwd(), ".gitignore")
    try:
        with open(gitPath, "r") as ignore:
            lines = ignore.readlines()
        for line in lines:
            if f"# automatically added by {__file__}" in line:
                return None
    except:
        pass

    with open(gitPath, "a") as ignore:
        ignore.write(message)
    return None


def currentFilePath() -> str:
    """fetches path to this script"""
    return os.path.abspath(__file__)

def ignoreInEncryption() -> List[str]:
    allFilesList = getAllFiles()
    ignoredYamls = [path for path in allFilesList if path.endswith(".yaml")]
    ignoredEncrs = [path for path in allFilesList if path.endswith(_encrExtension)]

    ignoredFilesList = [currentFilePath(), os.path.join(os.getcwd(), ".gitignore")]
    ignoredFilesList.extend(ignoredYamls)
    ignoredFilesList.extend(ignoredEncrs)

    return ignoredFilesList

def getFilesForDecription() -> List[str]:
    """fetches all files that can be decrypted"""
    allFiles = getAllFiles()
    return [path for path in allFiles if path.endswith(_encrExtension)]

def Main() -> None:
    """encrypts or decrypts all 'legal' files.
    simultaneously updating .gitignore file"""
    choice = input("Would you like to (E)ncrypt or (D)ecrypt?: ")

    if choice.lower() == 'e':
        allFiles = getAllFiles()
        ignoredFiles = ignoreInEncryption()
        toEncript = [path for path in allFiles if path not in ignoredFiles]
        if (len(toEncript) == 0):
            sys.exit("No files to encrypt")
        updateGitIgnore()
        key = getKey(getPassword())
        for path in toEncript:
            encrypt(key, path)
        print("Done.")

    elif choice.lower() == 'd':
        filesForDecription = getFilesForDecription()
        if (len(filesForDecription) == 0):
            sys.exit("No files to decrypt")
        updateGitIgnore()
        key = getKey(getPassword())
        for path in filesForDecription:
            decrypt(key, path)
        print("Done.")

    else:
        sys.exit("No Option selected, closing...")

    return None

if __name__ == '__main__':
    Main()



