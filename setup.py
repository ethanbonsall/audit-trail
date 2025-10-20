from setuptools import setup, find_packages

setup(
    name="audittrail",
    version="0.1.0",
    packages=find_packages(),
    install_requires=["fastapi", "starlette", "click"],
    author="Ethan P. Bonsall",
    description="A lightweight, tamper-proof audit trail library for Python web frameworks.",
    url="https://github.com/ethanbonsall/audittrail-py",
    python_requires=">=3.8",
    entry_points={
    "console_scripts": ["audittrail=audittrail.cli:cli"]
},
)