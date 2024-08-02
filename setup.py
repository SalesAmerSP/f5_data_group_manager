from setuptools import setup, find_packages

setup(
    name='f5-dgm',
    version='0.9a',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'flask',
        'requests',
        'flask-talisman',
        'urllib3',
        'talisman',
        'requests',
        'cryptography'
    ],
    entry_points={
        'console_scripts': [
            'run-myapp=run:app.run',
        ],
    },
)
