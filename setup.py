from setuptools import setup, find_packages


setup(
    name='asn_report',
    description='Webserver graphs most common network ASes traffic goes to',
    url='https://github.com/coxley/asn_report',
    version=1.0,
    author='Codey Oxley',
    license='MIT',
    packages=find_packages(),
    include_package_data=True,
    setup_requires = [ "setuptools_git >= 0.3", ],
    exclude_package_data = {'': ['.gitignore']},
    package_data={'': ['ip_to_asn.db'],
                  'templates': ['templates/*']},
    entry_points='''
    [console_scripts]
    asn_capture=asn_report.asn_capture:main
    asn_report=asn_report.asn_webserver:main
    asn_create_db=asn_report.asn_capture:create_db
    '''
)
