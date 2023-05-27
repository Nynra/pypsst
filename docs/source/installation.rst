installation
================

For now it is not possible to download the package from PyPI, so you have to install it manually.

First install the dependencies:

.. code-block:: bash

    python3 -m venv .venv
    source .venv/bin/activate
    python3 -m pip install --upgrade pip
    pip install wheel
    pip install -r requirements.txt
    pip install build


Then build the package:

.. code-block:: bash

    python3 -m build


Finally install the package:

.. code-block:: bash

    pip install dist/PyPsst-x.x.x-py3-none-any.whl

.. note::
    The package will only be installed in the currently active virtual environment.