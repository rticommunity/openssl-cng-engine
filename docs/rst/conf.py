import os
import sys
import sphinx_rtd_theme

extensions = [
    'sphinx_rtd_theme',
]

project = 'OpenSSL CNG Engine'
copyright = '2020 Real-Time Innovations, Inc. (RTI)'

highlight_language = 'c'
html_theme = 'sphinx_rtd_theme'
html_logo = 'img/rti-logo.png'
html_favicon = 'img/favicon.ico'

html_theme_options = {
    # TOC options
    'collapse_navigation': False,
    'sticky_navigation': False,
}
