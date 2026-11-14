"""
Import wrapper so the bot shares smc36435.py's fingerprint logic and key DB.
Drop smc36435.py in the same directory.
"""
import importlib.util, pathlib

_here = pathlib.Path(__file__).parent
_spec = importlib.util.spec_from_file_location("smc36435", _here / "smc36435.py")
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

BMC = _mod.BMC
KeyDB = _mod.KeyDB
FIXED = _mod.FIXED
POSTEX = _mod.POSTEX
