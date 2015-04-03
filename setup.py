from setuptools import setup


setup(
    name='asn_report',
    description='Webserver graphs most common network ASes traffic goes to',
    url='https://github.com/coxley/asn_report',
    version=1.0,
    author='Codey Oxley',
    packages=['asn_report'],
    py_modules=['asn_capture', 'asn_webserver'],
    entry_points='''
    [console_scripts]
    interface_monitor=interface_monitor.interface_monitor:main
    asn_capture=asn_capture:main
    asn_report=asn_webserver:main
    '''
)
