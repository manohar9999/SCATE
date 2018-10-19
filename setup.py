from setuptools import setup, find_packages
import sys

if sys.version_info < (3,):
    raise ImportError(
    """You are running SCATE 1.0 on Python 2.
    Please upgrade to Python 3 and try again.
    """)

install_requires = [
    'lxml>=4.2.5',
    'pyparsing>=2.2.0',
    'suds-py3>=1.3.3.0',
    'python-docx>=0.8.7',
]

setup(
    name='SCATE',
    version='1.0',
    python_requires=">=3.4",
    packages=find_packages(),
    include_package_data=True,
    author='Lakshmi Manohar Rao Velicheti',
    author_email='manoharvelicheti@gmail.com',
    license='Other/Proprietary License',
    description='Static Code Analysis Tool Evaluator',
    long_description='Static Code Analysis Tool Evaluator (SCATE) is a framework for evaluating the quality of a static code analysis (SCA) tool, and modeling its behavior.',
    url='https://github.com/manohar9999/SCATE',
)