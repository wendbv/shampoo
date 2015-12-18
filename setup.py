from distutils.core import setup


setup(
    name='shampoo',
    packages=['shampoo'],
    version='0.1.0b4',
    description='Shampoo is a asyncio websocket protocol implementation for Autobahn',
    author='Daan Porru (Wend)',
    author_email='daan@wend.nl',
    license='MIT',
    url='https://github.com/wendbv/shampoo',
    keywords=['websocket', 'protocol'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Python :: 3.5',
    ],
    install_requires=['schemavalidator', 'autobahn==0.10.9'],
    extras_require={
        'test': ['pytest', 'pytest-cov', 'coverage', 'pytest-mock', 'coveralls'],
    }
)
