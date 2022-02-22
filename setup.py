from setuptools import setup
import sys
# Python 2 vs 3 requirements
if sys.version_info[0] == 2:
    reqs = ["scapy>=2.4", "ipaddress", "future", "twisted", "netifaces"]
else:
    reqs = ["scapy>=2.4", "twisted", "netifaces"]

setup(name='mitm6',
      version='0.3.0',
      description='Pwning IPv4 via IPv6',
      license='GPLv2',
      classifiers=[
        'Intended Audience :: Information Technology',
        'Framework :: Twisted',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
      ],
      author='Dirk-jan Mollema / Fox-IT',
      author_email='dirkjan.mollema@fox-it.com',
      url='https://github.com/dirkjanm/mitm6/',
      packages=['mitm6'],
      install_requires=reqs,
      entry_points= {
        'console_scripts': ['mitm6=mitm6.mitm6:main']
      }
     )
