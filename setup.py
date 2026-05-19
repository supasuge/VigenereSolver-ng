"""Legacy setup.py shim.
    python -m build           # produces sdist + wheel in dist/
    python -m twine upload dist/*
"""
from setuptools import setup

setup()
