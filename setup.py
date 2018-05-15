from distutils.core import setup, Extension

INSTALL_REQUIRES = ['msgpack-python', 'pynacl'] #'pysha3',# TODO: Add cryptography wheel

TESTS_REQUIRE = [
    'pytest',
    'coverage',
    'pytest-cov',
    'pdbpp',
    'ipython'
]

setup(name='umbral',
      version='0.1',
      description='Umbral PRE implementation for NuCypher',
      extras_require={'testing': TESTS_REQUIRE},
      install_requires=INSTALL_REQUIRES,
      packages=['umbral'])
