@echo off
REM STRYX Build Script for Windows
REM Usage: build.bat [clean|build|publish|test|lint]

setlocal

set CMD=%1
if "%CMD%"=="" set CMD=build

if "%CMD%"=="clean" goto :clean
if "%CMD%"=="build" goto :build
if "%CMD%"=="publish" goto :publish
if "%CMD%"=="publish-test" goto :publish-test
if "%CMD%"=="test" goto :test
if "%CMD%"=="lint" goto :lint
if "%CMD%"=="check" goto :check
if "%CMD%"=="help" goto :help
echo Unknown command: %CMD%
goto :help

:clean
echo Cleaning build artifacts...
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build
if exist *.egg-info rmdir /s /q *.egg-info
if exist stryx\*.egg-info rmdir /s /q stryx\*.egg-info
if exist .pytest_cache rmdir /s /q .pytest_cache
if exist .mypy_cache rmdir /s /q .mypy_cache
if exist .ruff_cache rmdir /s /q .ruff_cache
for /d /r . %%d in (__pycache__) do if exist "%%d" rmdir /s /q "%%d" 2>nul
echo Done.
goto :eof

:build
echo Installing build tools...
pip install build
echo Building package...
python -m build
echo.
echo Packages built in dist\:
dir dist\
goto :eof

:publish
echo Building package...
pip install build twine
python -m build
echo Uploading to PyPI...
twine upload dist/*
goto :eof

:publish-test
echo Building package...
pip install build twine
python -m build
echo Uploading to TestPyPI...
twine upload --repository testpypi dist/*
goto :eof

:test
echo Installing dev dependencies...
pip install -e ".[dev,xml]"
echo Running tests...
python -m pytest tests/ -v --tb=short
goto :eof

:lint
echo Running linting...
pip install ruff
python -m ruff check stryx/ --fix
python -m ruff format stryx/
goto :eof

:check
echo Verifying package...
pip install twine build
python -m build
twine check dist/*
echo.
echo Package verification passed!
goto :eof

:help
echo STRYX Build Commands:
echo   build       - Build sdist and wheel distributions
echo   clean       - Clean build artifacts
echo   publish     - Build and publish to PyPI
echo   publish-test- Build and publish to TestPyPI
echo   test        - Run tests
echo   lint        - Run linting
echo   check       - Verify package is well-formed
echo   help        - Show this help
goto :eof
