from __future__ import unicode_literals
import sys
from typing import Tuple
import zipfile
import json
from hashlib import md5
import os
import re
import filetype
from filetype.types import Type

def hashed_filename(s: str) -> str:
    t = md5()
    t.update(s.encode())
    return t.hexdigest()

def safe_mkdir(s: str):
    try:
        os.mkdir(s)
    except FileExistsError:
        pass

def genkey(s: str) -> int:
    ret = 0
    for i in s:
        ret = (ret * 31 + ord(i)) & 0xffffffff
    if ret & 0x80000000:
        ret = ret | 0xffffffff00000000
    return ret

def decrypt(key: int, data: bytes) -> bytes:
    ret = []
    for slice in [data[i:i+1024] for i in range(0, len(data), 1024)]:
        tmpkey = key
        for i in slice:
            tmpkey = (65535 & 2531011 + 214013 * tmpkey >> 16) & 0xffffffff
            ret.append((tmpkey & 0xff) ^ i)
    return bytes(ret)

match_rule = re.compile(r"^[0-9a-f]{32}.bin3?$")
def is_encrypted_file(s: str) -> bool:
    if match_rule.match(s) != None:
        return True
    return False

def travels_dict(dic: dict):
    for k in dic:
        if type(dic[k]) == dict:
            for p, v in travels_dict(dic[k]):
                yield f"{k}_{p}", v
        elif type(dic[k]) == list:
            for p, v in travels_list(dic[k]):
                yield f"{k}_{p}", v
        else:
            yield str(k), dic[k]
        
def travels_list(vals: list):
    for i in range(len(vals)):
        if type(vals[i]) == dict:
            for p, v in travels_dict(vals[i]):
                yield f"{i}_{p}", v
        elif type(vals[i]) == list:
            for p, v in travels_list(vals[i]):
                yield f"{i}_{p}", v
        else:
            yield str(i), vals[i]


class Moc3(Type):
    MIME = "application/moc3"
    EXTENSION = "moc3"
    def __init__(self):
        super(Moc3, self).__init__(mime=Moc3.MIME, extension=Moc3.EXTENSION)
    
    def match(self, buf):
        return len(buf) > 3 and buf.startswith(b"MOC3")

class Moc(Type):
    MIME = "application/moc"
    EXTENSION = "moc"
    def __init__(self):
        super(Moc, self).__init__(mime=Moc.MIME, extension=Moc.EXTENSION)
    
    def match(self, buf):
        return len(buf) > 3 and buf.startswith(b"moc")

filetype.add_type(Moc3())
filetype.add_type(Moc())

def guess_type(data: bytes):
    ftype = filetype.guess(data)
    if ftype != None:
        return "." + ftype.extension
    try:
        json.loads(data.decode("utf8"))
        return ".json"
    except:
        return ""

class LpkLoader():
    def __init__(self, lpkpath, configpath) -> None:
        self.lpkpath = lpkpath
        self.configpath = configpath
        self.trans = {}
        self.entrys = {}
        self.load_lpk()
    
    def load_lpk(self):
        self.lpkfile = zipfile.ZipFile(self.lpkpath)
        config_mlve_raw = self.lpkfile.read(hashed_filename("config.mlve")).decode()
        self.mlve_config = json.loads(config_mlve_raw)
        if self.mlve_config["type"] == "STM_1_0":
            self.load_config()
    
    def load_config(self):
        self.config = json.loads(open(self.configpath, "r", encoding="utf8").read())

    def extract(self, outputdir: str):
        for chara in self.mlve_config["list"]:

            subdir = outputdir + (chara["character"] if chara["character"] != "" else "character") + "/"
            safe_mkdir(subdir)

            for i in range(len(chara["costume"])):
                self.extract_costume(chara["costume"][i], subdir, i)

            for name in self.entrys:
                out_s: str = self.entrys[name]
                for k in self.trans:
                    out_s = out_s.replace(k, self.trans[k])
                open(subdir+name, "w", encoding="utf8").write(out_s)
    
    def extract_costume(self, costume: list, dir: str, id: int):
        subdir = dir
        if costume["path"] == "":
            return

        filename :str = costume["path"]
        entry_s = self.decrypt_file(filename).decode(encoding="utf8")
        entry = json.loads(entry_s)

        for name, val in travels_dict(entry):
            if type(val) == str and is_encrypted_file(val):
                if val in self.trans:
                    continue
                name += f"_{id}"
                _, suffix = self.recovery(val, subdir + name)
                self.trans[val] = name + suffix

        self.trans[costume["path"]] = f"model{id}.json"

        out_s = json.dumps(entry, ensure_ascii=False)
        self.entrys[f"model{id}.json"] = out_s

    def recovery(self, filename, output) -> Tuple[bytes, str]:
        ret = self.decrypt_file(filename)
        suffix = guess_type(ret)
        print(f"recovering {filename} -> {output+suffix}")
        open(output + suffix, "wb").write(ret)
        return ret, suffix

    def getkey(self, file: str):
        if self.mlve_config["type"] == "STM_1_0" and self.mlve_config["encrypt"] != "true":
            return 0

        if self.mlve_config["type"] == "STM_1_0":
            return genkey(self.mlve_config["id"] + self.config["fileId"] + file + self.config["metaData"])
        elif self.mlve_config["type"] == "STD2_0":
            return genkey(self.mlve_config["id"] + file)
        else:
            raise Exception(f"not support type {self.mlve_config['type']}")

    def decrypt_file(self, filename) -> bytes:
        data = self.lpkfile.read(filename)
        return self.decrypt_data(filename, data)

    def decrypt_data(self, filename: str, data: bytes) -> bytes:
        key = self.getkey(filename)
        return decrypt(key, data)

if __name__ == "__main__":
    try:
        lpkpath = sys.argv[1]
        outputdir = sys.argv[2]
        if len(sys.argv) > 3:
            configpath = sys.argv[3]
        else:
            configpath = None
    except:
        print(f"usage: .\lpk.exe [target filename(usually ends with .lpk)] [output directory] [config.json path]")
        try:
            exit(0)
            loader = LpkLoader(lpkpath, configpath)
            if not outputdir.endswith("/"):
                outputdir = outputdir + "/"
            loader.extract(outputdir)
        except NameError:
            print('[NoOperationException]')
