import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="easysocks5",
    version="0.0.4",
    author="Frank Chang",
    author_email="frank@csie.io",
    description="easysocks5 is a simple SOCKS5 server implementation with AsyncIO",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/frankurcrazy/easysocks5",
    packages=setuptools.find_packages(),
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Internet",
        "Topic :: System :: Networking",
    ],
    keywords=["socks", "socks5", "asyncio"],
    python_requires='>=3.7',
)
