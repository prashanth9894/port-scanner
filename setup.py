<<<<<<< HEAD
from setuptools import setup, find_packages

setup(
    name="port-scanner",
    version="1.0.0",
    description="A command-line port scanner utility",
    author="Prashanth",
    author_email="prashanth9894@example.com",
    url="https://github.com/prashanth9894/port-scanner",
    py_modules=["port_scanner"],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "port-scanner=port_scanner:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
=======
from setuptools import setup, find_packages

setup(
    name="port-scanner",
    version="1.0.0",
    description="A command-line port scanner utility",
    author="Prashanth",
    author_email="prashanth9894@example.com",
    url="https://github.com/prashanth9894/port-scanner",
    py_modules=["port_scanner"],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "port-scanner=port_scanner:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
>>>>>>> 841760e (Add setup.py and rename port to port_scanner; installable package)
