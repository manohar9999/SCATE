#!/bin/env python

################################################################################
#
# file : Utilities.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
##
################################################################################


import sys
import os
from lib.DataAbstractions import ResultSet, Granularity
from lib.DataManagers.XMLManager import XMLManager
import logging
import inspect
import subprocess


#
# Imports and returns user-defined classes in the provided
# prefix/imports directory.
#
def import_classes(prefix, imports, required_function=None):
    logging.debug('Importing classes from %s/%s' % (prefix, imports))
    objects = []

    # Evaluate each of the installed pre-commit hooks.
    for name in os.listdir(os.path.join(prefix, imports)):
        if name.endswith(".py") and name != '__init__.py':
            #
            # Helper method that extracts the modules name from the provided
            # Python script name.
            #
            def get_module_basename(script):
                return script[0:len(script) - 3]

            # Import the modules
            module_basename = get_module_basename(name)
            module_name = imports.replace('/', '.') + '.' + module_basename
            module = __import__(module_name, locals(), [], 1)

            # Find the user-defined classes (skip imports)
            for cls_name, cls in inspect.getmembers(module, inspect.isclass):
                if inspect.getmodule(cls) == module:

                    # Skip classes which do not have the required function
                    if required_function:
                        found = False
                        for func_name, func_ptr in inspect.getmembers(cls):
                            if func_name == required_function:
                                found = True
                                break
                        if not found:
                            continue

                    objects.append(cls)

    logging.debug('Found classes: %s' % objects)
    return objects


#
# Imports and returns the DataManager classes
#
def get_datamanagers():
    script_path = os.path.dirname(os.path.abspath(sys.argv[0]))
    return import_classes(script_path, 'lib/DataManagers')


#
# Imports and return the DataPointFactory classes
#
def get_datapointfactories():
    script_path = os.path.dirname(os.path.abspath(sys.argv[0]))
    return import_classes(script_path, 'lib/DataPointFactories')


#
# Execute the provided command
#
def run_cmd(cmd, stdin=None, stdout=None, stderr=None):
    logging.debug("Executing shell command: '%s'" % " ".join(cmd))
    subprocess.call(cmd, stdin=stdin, stdout=stdout, stderr=stderr)


#
# Stringify the provided args
#
def stringify_args(args, delimiter='|'):
    pairs = []
    for (key, value) in args._get_kwargs():
        if key in ['username', 'password']:
            continue

        if inspect.isclass(value):
            value = value.__name__

        pairs.append('='.join([key, str(value)]))
    return delimiter.join(pairs)


#
# Convert the provided args string into a dictonary
#
def dictify_args(args, delimiter='|'):
    result = {}

    for pair in args.split(delimiter):
        (key, value) = pair.split('=')
        if value == 'None':
            value = None
        if value == 'True':
            value = True
        if value == 'False':
            value = False
        result[key] = value
    return result


#
# @Param in :  prefix - path
# @Param in : imports - imports Tools
# @Param in : factory - factory is supposed to create and return tool objects
# @returns : all the tools objects
#
# This function is used along with get_tools functions
#
def import_objects(prefix, imports, factory):
    objects = []

    # Evaluate each of the installed pre-commit hooks.

    for name in os.listdir(os.path.join(prefix, imports)):
        if name.endswith(".py") and name != '__init__.py':
            # Helper method that extracts the modules name from the provided
            # Python script name.
            def get_module_basename(script):
                return script[0:len(script) - 3]

            # Import the __create__ function for the project module.
            module_basename = get_module_basename(name)
            module_name = imports.replace('/', '.') + '.' + module_basename
            hook = __import__(module_name, globals(), locals(), [factory])

            if factory in dir(hook):
                eval_str = 'hook.%s ()' % factory
                objects.append(eval(eval_str))
            else:
                print("*** warning: skipping %s; %s not defined" % (module_name, factory))

    return objects


#
# Uses the import_objects functions and returns all Report Generators objects
#
def get_reportgenerators():
    script_path = os.path.dirname(os.path.abspath(sys.argv[0]))
    return import_objects(script_path, 'lib/ReportGenerators', '__create__')


#
# Determines if the provided resultset needs to use the min/max criteria
#
def needs_min_max(rs):
    if len(rs.builds) == 1:
        return False

    for tool in get_tools():
        if tool.name() in rs.builds:
            if not tool().supports_granularity(Granularity.LINE):
                return True
    return False


def resolve_relative_path(filename, base_directory, skip_folders: set = set()):
    """
    Find the file with name 'filename' inside 'base_directory' and return the relative path.
    >>> import shutil
    >>> os.path.exists("/tmp/test_resolve_relative_path")
    False
    >>> os.makedirs('/tmp/test_resolve_relative_path/1/2/3/4/5/6/7/8/9/', exist_ok=True)
    >>> os.makedirs('/tmp/test_resolve_relative_path/2/1/3/4/5/6/7/8/9/', exist_ok=True)
    >>> os.makedirs('/tmp/test_resolve_relative_path/2/2/3/4/6/7/8/5/4/', exist_ok=True)
    >>> with open('/tmp/test_resolve_relative_path/1/2/3/4/5/6/7/8/test_resolve_relative_path.txt', 'w+') as file:
    ...     file.write("TEST")
    4
    >>> resolve_relative_path('test_resolve_relative_path.txt', '/tmp/test_resolve_relative_path')
    '1/2/3/4/5/6/7/8/test_resolve_relative_path.txt'
    >>> resolve_relative_path('test_resolve_relative_path.txt', '/tmp/test_resolve_relative_path', skip_folders={'1'})
    Traceback (most recent call last):
    FileNotFoundError: test_resolve_relative_path.txt not found in /tmp/test_resolve_relative_path
    >>> resolve_relative_path('test_resolve_relative_path.txt', '/tmp/test_resolve_relative_path/1/2/3/4')
    '5/6/7/8/test_resolve_relative_path.txt'
    >>> resolve_relative_path('test_resolve_relative_path.txt', '/tmp/test_resolve_relative_path/1/2/3/4/5/6/7/8')
    'test_resolve_relative_path.txt'
    >>> resolve_relative_path('test_resolve_relative_path.txt', '/tmp/test_resolve_relative_path/2')
    Traceback (most recent call last):
    FileNotFoundError: test_resolve_relative_path.txt not found in /tmp/test_resolve_relative_path/2
    >>> shutil.rmtree('/tmp/test_resolve_relative_path')

    :param filename:
    :param base_directory:
    :return:
    """

    def find_absolute_path_to_file(search_directory):
        logging.debug("Checking %s for file with name '%s'" % (search_directory, filename))
        if not os.path.isabs(search_directory):
            search_directory = os.path.abspath(search_directory)

        listings = os.listdir(search_directory)

        for listing in listings:
            path = os.path.join(search_directory, listing)

            # Search files at this level
            if os.path.isfile(path):
                if listing == filename:
                    return path

            # Recurse into each folder
            if os.path.isdir(path):
                if listing not in skip_folders:
                    result = find_absolute_path_to_file(path)

                    if result:
                        return result

        return None

    absolute_path = find_absolute_path_to_file(base_directory)

    if not absolute_path:
        raise FileNotFoundError("%s not found in %s" % (filename, base_directory))

    return os.path.relpath(absolute_path, base_directory)