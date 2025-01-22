from pathlib import Path
import setuptools

__version__ = "0.0.1"

info = Path(__file__).with_name("README.md").read_text(encoding="utf8")

setuptools.setup(
    name="apkrepotool",
    url="https://github.com/obfusk/apkrepotool",
    description="manage APK repos",
    long_description=info,
    long_description_content_type="text/markdown",
    version=__version__,
    author="FC (Fay) Stegerman",
    author_email="flx@obfusk.net",
    license="AGPLv3+",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: Linux",
        "Operating System :: POSIX",
        "Operating System :: Unix",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
      # "Programming Language :: Python :: 3.14",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Software Development",
        "Topic :: Utilities",
    ],
    keywords="android apk repo",
    entry_points=dict(console_scripts=["apkrepotool = apkrepotool:main"]),
    packages=["apkrepotool"],
    package_data=dict(apkrepotool=["py.typed", "schemas/*.json"]),
    python_requires=">=3.9",
    install_requires=["click>=6.0", "jsonschema", "repro-apk>=0.2.7", "ruamel.yaml"],
)
