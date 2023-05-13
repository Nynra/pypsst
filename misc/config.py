import configparser
from typing import Union
from ast import literal_eval
import os
from .tools.utils import Utils


class Config:
    """
    Class to handle the cli config.
    
    Class manages the information in the config file.
    The sections are named as follows:
        <type>.<id>

    Where <id> is the part ID and not the id in the system (axis id).

    The config first looks in the <type>.<id> section and then in the
    <type>.DEFAULT section for fallback values. If the key is not found
    in either section, a KeyError is raised.
    """

    def __init__(self, filename : str='./config.ini') -> ...:
        """
        Initialize the settings.

        Parameters
        ----------
        filename: str
            The filename of the settings file. If only a filename is given
            the directory of the module is used as the path. If the current
            working directory should be used, the path should be given as
            './filename.ini'.
        """
        # Check if the filename is a file or a path
        if not isinstance(filename, str):
            raise TypeError(f'filename must be a string, not {type(filename)}')

        # Check if the filename is a path
        if '/' in filename and not os.path.isabs(filename):
            filename = os.path.abspath(filename)
        else:
            # The file is in the module directory
            filename = os.path.dirname(os.path.abspath(__file__)) + '/' + filename

        # Check if the file exists
        if not Utils.file_exists(filename):
            raise FileNotFoundError(f'File {filename} not found.')
        
        # Load the settings
        self._config = configparser.ConfigParser()
        self._config.read(filename)

    # FUNCTIONS
    def get(self, section : str, key : str) -> Union[str, int, float, bool]:
        """
        Get the value of a key in a specific section.
        
        Will look in the given section first and uses the type.DEFAULT section
        for fallback values.

        Parameters
        ----------
        section: str
            The section to look in.
        key: str
            The key to look for.

        Raises
        ------
        KeyError
            If the key is not found in the given section or the default section.

        Returns
        -------
        value: str, int, float, bool
            The value of the key.
        """
        if not isinstance(section, str):
            raise TypeError(f'section must be a string, not {type(section)}')
        if not isinstance(key, str):
            raise TypeError(f'key must be a string, not {type(key)}')
        
        val = self._config.get(section, key, fallback=None)
        if val is None:  # Look in the default section
            val = self._config.get(section.split('.')[0]+'.DEFAULT', key, fallback=None)

        if val is None:  # Key not found
            raise KeyError(f'Key {key} not found in section {section}')

        # Check which type the value is
        if val.lower() == 'true' or val.lower() == 'false':
            val = True if val.lower() == 'true' else False
        elif '[' in val and ']' in val:
            raise NotImplementedError('List values are not supported yet.')
        elif '(' in val and ')' in val:
            raise NotImplementedError('Tuple values are not supported yet.')
        elif val.isdigit() and '.' in val:
            val = float(val)
        elif val.isdigit():
            val = int(val)
        else:
            # Assume it is a string
            val = str(val)

        return val

    def set(self, section : str, key : str, value : Union[str, int, float, bool]) -> ...:
        """
        Set the value of a key in a specific section.
        
        .. attention::

            It is not allowed to change settings in DEFAULT sections.
            If the setting should be changed this had to be done by hand
            in the settings file.

        Parameters
        ----------
        section: str
            The section to look in.
        key: str
            The key to look for.
        value: str, int, float, bool
            The value to set the key to.

        Raises
        ------
        KeyError
            If the user tries to change a setting in the DEFAULT section.
        """
        if not isinstance(section, str):
            raise TypeError(f'section must be a string, not {type(section)}')
        if not isinstance(key, str):
            raise TypeError(f'key must be a string, not {type(key)}')
        if not isinstance(value, (str, int, float, bool)):
            raise TypeError(f'value must be a string, int, float or bool, not {type(value)}')
        
        # Check if the section is a DEFAULT section
        if section.split('.')[-1] == 'DEFAULT':
            raise KeyError(f'Changing settings in DEFAULT sections is not allowed.')

        if section not in self._config.sections():
            raise KeyError(f'Section {section} not found.')

        # Set the value
        self._config[section][key] = str(value)

    def save(self, filename : Union[str, None]=None) -> None:
        """Save the settings to the file."""
        if filename is None:
            filename = self._filename
        path = os.path.dirname(os.path.abspath(__file__)) + '\\' + filename
        with open(path, 'w') as configfile:
            self._config.write(configfile)

