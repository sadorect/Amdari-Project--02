"""THROWAWAY: proves the Semgrep gate fails."""
import subprocess
from flask import request


def run():
    subprocess.run(request.args["cmd"], shell=True)
    return eval(request.args["expr"])
