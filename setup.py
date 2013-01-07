from setuptools import setup, find_packages

setup(
    name = "django-oauth2server",
    version = "0.4.1",
    author = "Alex Leigh",
    author_email = "leigh@alexleigh.me",
    description = "Django OAuth 2.0 Server",
    license = "MIT License",
    keywords = "django oauth2 server",
    url = "https://github.com/alexleigh/django-oauth2server",
    include_package_data = True,
    packages = find_packages()
)
