from setuptools import setup, find_packages

setup(
    name='dns_server',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'dnslib',
    ],
    entry_points={
        'console_scripts': [
            'dns-server=dns_server.cli:main',
        ],
    },
)