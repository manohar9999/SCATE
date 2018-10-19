from setuptools import setup, find_packages


install_requires = [
    'lxml>=4.2.5',
    'pyparsing>=2.2.0',
    'suds-py3>=1.3.3.0',
    'python-docx>=0.8.7',
]

setup(
    name='SCATE',
    version='1.0',
    packages=find_packages(),
    include_package_data=True,
    author='Lakshmi Manohar Rao Velicheti',
    author_email='manoharvelicheti@gmail.com',
    license='Other/Proprietary License',
    description='Static Code Analysis Tool Evaluator',
    long_description='Static Code Analysis Tool Evaluator (SCATE) is a framework for evaluating the quality of a static code analysis (SCA) tool, and modeling its behavior.',
    url='https://github.com/manohar9999/SCATE',
)
