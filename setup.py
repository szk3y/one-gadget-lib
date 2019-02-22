import setuptools

with open('README.md', 'r') as f:
    long_description = f.read()

install_requires = [
    'capstone',
    'pyelftools',
]

setuptools.setup(
    name='one_gadget',
    version='1.1.0',
    author='szk3y',
    install_requires=install_requires,
    author_email='d4tt423@gmail.com',
    description='A python library to find one-gadget',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/szk3y/one-gadget-lib',
    packages=setuptools.find_packages(),
    classifiers=(
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    )
)
