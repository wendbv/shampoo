from distutils.core import setup


setup(
    name='shampoo',
    packages=['shampoo'],
    package_data={'shampoo': ['schemas/*.json']},
    version='0.1.0b10',
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
    install_requires=['schemavalidator==0.1.0b6', 'autobahn==0.13.0'],
    extras_require={
        'test': ['pytest', 'pytest-cov', 'coverage', 'pytest-mock', 'coveralls'],
    }
)
