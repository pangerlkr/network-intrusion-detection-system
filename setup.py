"""Setup configuration for NIDS package."""
import os
from setuptools import setup, find_packages

# Read README for long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="network-intrusion-detection-system",
    version="0.1.0",
    author="pangerlkr",
    author_email="contact@pangerlkr.link",
    description="ML-powered Network Intrusion Detection System with real-time packet analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pangerlkr/network-intrusion-detection-system",
    project_urls={
        "Bug Tracker": "https://github.com/pangerlkr/network-intrusion-detection-system/issues",
        "Documentation": "https://pangerlkr.github.io/network-intrusion-detection-system/",
        "Source Code": "https://github.com/pangerlkr/network-intrusion-detection-system",
    },
    packages=find_packages(exclude=["tests", "tests.*", "docs", "data"]),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=22.0.0",
            "isort>=5.10.0",
            "pylint>=2.13.0",
        ],
        "docs": [
            "sphinx>=4.5.0",
            "sphinx-rtd-theme>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "nids=main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords="nids intrusion detection security ml machine-learning cybersecurity network-security anomaly-detection",
)
