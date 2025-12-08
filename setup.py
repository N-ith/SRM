from setuptools import setup, find_packages

setup(
    name="srm",
    version="1.0.0",
    description="Secure file deletion tool with cryptographic guarantees",
    author="Nith-AN",
    packages=find_packages(),
    install_requires=[
        "cryptography>=41.0.0",
    ],
    entry_points={
        "console_scripts": [
            "srm=srm.cli:main",
        ],
    },
    python_requires=">=3.8",
)