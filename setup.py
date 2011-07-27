__doc__ = open('README.rst').read()
__doc__ += """

Links
-----

* `source <https://github.com/spantaleev/roscraco>`_
"""

from setuptools import setup, find_packages

import roscraco


setup(
    name = "roscraco",
    version = roscraco.__version__,
    description = "A library for managing home routers (networking equipment).",
    long_description = __doc__,
    author = "Slavi Pantaleev",
    author_email = "s.pantaleev@gmail.com",
    url = "https://github.com/spantaleev/roscraco",
    keywords = ["router", "networking", "tplink",
                "canyon", "netgear", "zyxel", "tomato"],
    platforms = "any",
    license = "BSD",
    packages = find_packages(),
    install_requires = [],
    classifiers = [
        "Programming Language :: Python",
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Telecommunications Industry",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: System :: Networking",
        "Topic :: Home Automation",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ]
)

