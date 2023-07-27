from setuptools import setup

setup(
    name="Pypsst",
    version="0.0.4",
    author="Nynra",
    description="A Python package for simple encryption tasks",
    py_modules=["pypsst"],
    package_dir={"": "src"},
    install_requires=["pycryptodome", "rlp"],
    entry_points="""
        [console_scripts]
        pypsst=pypsst.cli.cli:cli
    """,
)
