from setuptools import setup, find_packages

setup(
    name="safeguard",
    version="0.1.0",
    description="A project for scanning secrets, configs, dependencies, and permissions",
    author="Your Name",
    packages=find_packages(),  
    install_requires=[
        "pyyaml==6.0.2",
        "requests==2.32.3",
        "packaging==25.0",
        "toml==0.10.2",
    ],
    python_requires=">=3.10",
)
