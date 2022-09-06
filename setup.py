from glob import glob
from os.path import basename
from os.path import splitext
from setuptools import find_packages
from setuptools import setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="container-image-scan",
    version="0.0.9",
    author="CrowdStrike",
    description="Script to scan a container and return response codes indicating pass/fail",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/crowdstrike/container-image-scan",
    packages=find_packages("."),
    package_dir={"": "."},
    py_modules=[splitext(basename(path))[0] for path in glob("*.py")],
    include_package_data=True,
    install_requires=[
        'docker',
        'crowdstrike-falconpy'
    ],
    extras_require={
        'devel': [
            'flake8',
            'pylint',
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Operating System :: Unix",
        "Operating System :: POSIX",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: The Unlicense (Unlicense)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
