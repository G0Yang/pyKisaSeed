import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

install_requires = [
    'cryptography==36.0.0',
    ]

setuptools.setup(
    name="seed128",
    version="1.0.0",
    author="ioumelon7, ender35841",
    author_email="ioumelon7@gmail.com, ender35841@gmail.com",
    description="KISA Seed 128 encrypt package",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/G0Yang/pySeed128",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)