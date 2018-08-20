import os
from setuptools import find_packages
from setuptools import setup
from setuptools.command.install import install

base_dir = os.path.dirname(__file__)

class Rename(install):
    def run(self):
        install.run(self)
        os.rename('/etc/helicopter/config.json.sample','/etc/helicopter/config.json')

setup(
    name='helicopter',
    version='1.0.0',
    description='Payload server daemon to monitor VirusTotal',
    author='@2xxeformyshirt',
    setup_requires=[
        'setuptools'
    ],
    license='GNU GPLv3',
    data_files=[
        ('/etc/helicopter',[]),
        ('/etc/helicopter/logs',[]),
        ('/etc/helicopter',['config.json.sample'])
    ],
    entry_points={
        'console_scripts': ['helicopter=helicopter.helicopter:main']
    },
    packages=find_packages(),
    cmdclass={
        'install': Rename
    }
)
