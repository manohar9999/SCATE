Static Code Analysis Tool Evaluator
===========================================

**Static Code Analysis Tool Evaluator (SCATE)** is a framework for evaluating 
the quality of a static code analysis (SCA) tool, and modeling its behavior. 
By behavior modeling, we mean creating a knowledge base that is able to 
understand when a given SCA tool will identify a potential flaw in the 
source code. SCATE is designed to be extensible to many different SCA tools, 
code bases, and reporting formats.

## System Requirements

* [Python 3.4](https://www.python.org/downloads/) or later
* [python-docx](https://pypi.python.org/pypi/python-docx)
* [pyparsing](https://pypi.python.org/pypi/pyparsing)
* [lxml](https://pypi.python.org/pypi/lxml)
* [suds](https://pypi.python.org/pypi/suds-py3)

## Quick Start

Use the ```--help``` option to see the different command-line options:

    ./SCATE.py --help

To see the help for a given command:
   
    ./SCATE.py [command] --help

## Simple Example

The following commands provide a simple example of how to run SCATE.
In this example, we will only be looking at CWE252.  There are four
basic commands in SCATE (import, build, analyze, and report).  Generic
options are available for all commands (debug, weaknesses, and threads),
whereas commands, tools, and other abstractions can have their own
specific arguments to change their behavior.

### Generic options

The following generic options can be used with any command:

* `--debug`: Enable debugging output
* `--weaknesses=[Weakness,...]`: Only perform the command for the specified weaknesses.  Weaknesses should match a 'CWE#' format
* `--threads=#`: Enable multithreaded behavior.  Some commands may not leverage threading

### Import

Import uses ImportSuites to build up a knowledge base of the known
flaws within source code.  Multiple ImportSuites can exist within
SCATE, so the ImportSuite you want to use must be provided:

    ./SCATE.py --weaknesses=CWE194 import --outfile=kb.xml --path=/path/to/juliet/directory/testcases  JulietCpp-1.2

### Build

Build uses the specified SCA tool to build and analyze the source code.
The output file from the import command is used to identify the compiler
to use, any arguments for the compiler, and what directory the compiler should
be run in.  The build command has its own specific arguments:

* `--ignore-compile`: Don't compile the source code with the SCA tool
* `--ignore-docgen`: Don't generate the result file for the SCA tool
* `--clean`: Clean the target directory and SCA results, if possible

Also, the SCA tool you want to use for the build must be specified.  Tools can have
their own arguments as well.  For example, if an SCA tool requires a server to report
it's results, the server address must be provided.

    ./SCATE.py --weaknesses=CWE194 build --importfile=kb.xml --outfile=build.xml [tool] [tool_arguments]

### Export

Export merges the results from the import and build commands and identifies the
true positives (TP), false positives (FP) and false negatives (FN).  Multiple
granularities (File, Function, and Line) are provided in the output  The export
command supports the following arguments:

* `--importfiles=[filename1,...]`: Import files to use
* `--buildfiles=[filename1,...]`: Build files to use
* `--outfile=filename`: Export output file name

As with Build SCA tools, the type of exporter must be specified.

    ./SCATE.py --weaknesses=CWE194 export --importfiles=kb.xml --buildfiles=build.xml --outfile=export.xml SCATE

### Report

Report uses the results from the export to generate a report.  Each ReportGenerator
handles one type of report and can specify their own additional arguments to change
their behavior (i.e. different output formats).

The following example generates CSV files in a pivot table format for each granularity:

    ./SCATE.py report --exportfile=export.xml pivot_table
