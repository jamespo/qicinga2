from setuptools import setup, find_packages

version = '0.1'

setup(name='qicinga2',
      python_requires='>3.2',
      version=version,
      description="Commandline interface to Icinga2 Status",
      long_description="""\
Commandline interface to Icinga Status""",
      classifiers=[],  # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='icinga monitoring commandline',
      author='James Powell',
      author_email='pydev@jamespo.org.uk',
      url='https://www.webscalability.com',
      license='',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      scripts=['scripts/qicinga2'],
      include_package_data=True,
      zip_safe=True,
      install_requires=[
        #
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
