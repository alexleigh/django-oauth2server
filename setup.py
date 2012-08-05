from setuptools import setup, find_packages

setup(
    name = "django-oauth2",
    version = "0.4",
    author = "Alex Leigh",
    author_email = "leigh@alexleigh.me",
    description = "Django OAuth 2.0 Server",
    license = "MIT License",
    keywords = "django oauth2",
    url = "https://github.com/atomatica/django-oauth2",
    include_package_data = True,
    packages = find_packages()
)
