from setuptools import setup, find_packages

setup(
    name='trivy-streamlit',
    version='0.7',
    packages=find_packages(),
    install_requires=[
        'streamlit',
    ],
    entry_points={
        'console_scripts': [
            'trivy-streamlit=trivy_streamlit.main_module:start_app',
        ],
    },
    # Additional metadata
    author='Michael Freeman',
    author_email='mfreeman451@gmail.com',
    description='A simple streamlit app for trivy security scanner JSON output',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/mfreeman451/trivy-streamlit',
    license='Apache-2.0',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Topic :: Security',
    ],
)

