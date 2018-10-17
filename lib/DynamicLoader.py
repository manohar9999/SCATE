import inspect
import logging
import os

class DynamicLoader:
  def __init__ (self, base, path, factoryMethod = '__create__'):
    self.__classes__ = []
    self.__base__ = base
    self.__path__ = path
    self.__factoryMethod__ = factoryMethod

  def loadClasses (self):
    logging.debug ('Loading classes from %s/%s' % (self.__base__, self.__path__))

    # Evaluate each of the installed pre-commit hooks.
    for name in os.listdir (os.path.join (self.__base__, self.__path__)):
      if not name.endswith (".py") or name == '__init__.py':
        continue

      #
      # Helper method that extracts the modules name from the provided
      # Python script name.
      #
      def getModuleBasename (script):
        return script[0:len (script) - 3]

      # Import the modules
      module_basename = getModuleBasename (name)
      module_name = self.__path__.replace ('/', '.') + '.' + module_basename
      module = __import__ (module_name, locals (), [], 1)

      # Find the user-defined classes (skip imports)
      for name, member in inspect.getmembers (module, inspect.isfunction):
        if name == self.__factoryMethod__:
          self.__classes__.append (member ())

  def getClasses (self):
    return self.__classes__