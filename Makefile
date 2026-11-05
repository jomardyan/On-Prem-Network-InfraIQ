# GNU Make; .NET SDK and the repository target packs are required.
ifeq ($(OS),Windows_NT)
PYTHON ?= python
else
PYTHON ?= python3
endif
DOTNET ?= dotnet
CONFIGURATION ?= Release
SOLUTION ?= Dev1.sln
PROJECT ?= Discovery.Web/Discovery.Web.csproj
PACKAGE_DIR ?= dist/web
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
.PHONY: help restore install dev build test lint check security package clean
help:
	@echo "restore - Restore NuGet dependencies; install also installs the Python project"
	@echo "build - Build the solution in CONFIGURATION"
	@echo "test - Run the repository tests after building"
	@echo "lint - Build with the repository code-style enforcement"
	@echo "check - Validate the .NET and Python implementations"
	@echo "python-install-dev - Install full Python development dependencies"
	@echo "python-build / python-package - Build Python wheel and source distribution"
	@echo "dotnet-test / python-test - Run one implementation explicitly"
	@echo "package - Publish the application without deployment"
	@echo "security - Report transitive NuGet vulnerability advisories"
	@echo "clean - Clean MSBuild outputs and the default dist folder"
	@echo "Override DOTNET, CONFIGURATION, SOLUTION, PROJECT and PACKAGE_DIR"
restore:
	"$(DOTNET)" restore "$(SOLUTION)" -p:Configuration="$(CONFIGURATION)"
install: restore python-install
build: restore
	"$(DOTNET)" build "$(SOLUTION)" -c "$(CONFIGURATION)" --no-restore
lint: restore
	"$(DOTNET)" build "$(SOLUTION)" -c "$(CONFIGURATION)" --no-restore -p:EnforceCodeStyleInBuild=true
test: dotnet-test python-test
dotnet-test: build
	"$(DOTNET)" test "Discovery.Tests/Discovery.Tests.csproj" -c "$(CONFIGURATION)" --no-build --no-restore
check: lint python-lint
	$(MAKE) test
security: restore python-security
	"$(DOTNET)" list "$(SOLUTION)" package --vulnerable --include-transitive
package: build
	"$(DOTNET)" publish "$(PROJECT)" -c "$(CONFIGURATION)" --no-restore --self-contained false -o "$(PACKAGE_DIR)"
clean:
	"$(DOTNET)" clean "$(SOLUTION)" -c "$(CONFIGURATION)"
	"$(PYTHON)" -c "from pathlib import Path; import shutil; root=Path.cwd().resolve(); p=root/'dist'; assert p.resolve().parent == root and not p.is_symlink(), 'Refusing unsafe generated-output cleanup'; shutil.rmtree(p) if p.is_dir() else None"
# Custom PACKAGE_DIR locations are preserved by clean.
dev:
	"$(DOTNET)" watch --project "$(PROJECT)" run --configuration Debug

# The repository contains both .NET applications and the Python distribution.
PYTHON_DIST_DIR ?= dist/python
.PHONY: python-install python-install-dev python-lint python-test python-build python-package python-security dotnet-test build-all package-all
python-install:
	"$(PYTHON)" -m pip install -e .
python-install-dev:
	"$(PYTHON)" -m pip install -e ".[dev]" build pip-audit pytest-timeout
python-lint:
	"$(PYTHON)" -m compileall -q onprem_network_infraiq tests/unit
python-test:
	"$(PYTHON)" -m pytest tests/unit --timeout=30 -W error::RuntimeWarning
python-build:
	"$(PYTHON)" -m build --outdir "$(PYTHON_DIST_DIR)"
python-package: python-build
python-security:
	"$(PYTHON)" -m pip_audit --local
build-all: build python-build
package-all: package python-package
