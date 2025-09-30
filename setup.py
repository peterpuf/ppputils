import setuptools
setuptools.setup(
    name="ppputils",
    version="0.0.2",
    author="puff",
    author_email="angrypuff333@gmail.com",
    description="ppp的utils",
    install_requires=['requests'],
    long_description=open("README.md", 'r').read(),
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)