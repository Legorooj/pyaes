from setuptools import setup, Extension
from Cython.Build import cythonize

ext_mods = [
    Extension('pyaes._aes_base', ['pyaes/_aes_base.pyx']),
    Extension('pyaes._mode_base', ['pyaes/_mode_base.pyx'])
]

setup(
    name='pyaes',
    version='2.0.0.dev0',
    python_requires='>=3.5',
    packages=['pyaes', 'pyaes.pure'],
    author='Legorooj',
    author_email='legorooj@protonmail.com',
    description='An implementation of AES in pure python and Cython',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/Legorooj/pyaes',
    install_requires=[
    ],
    license='MIT',
    classifiers=[
        'Intended Audience :: Developers',
        'Development Status :: 3 - Beta',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Security :: Cryptography',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries'
    ],
    ext_modules=cythonize(ext_mods)
)
