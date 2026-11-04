PYTHON ?= python3
.PHONY: install dev test lint build package security clean
install:
	dotnet restore "Dev1.sln"
dev: install
	@echo "Open Dev1.sln in your editor; use a local development environment."
build:
	dotnet build "Dev1.sln" -c Release
test: build
	dotnet test Discovery.Tests/Discovery.Tests.csproj -c Release --no-build
lint:
	dotnet build "Dev1.sln" -c Release -p:EnforceCodeStyleInBuild=true
security:
	dotnet list "Dev1.sln" package --vulnerable --include-transitive
package: build
	dotnet publish Discovery.Web/Discovery.Web.csproj -c Release --no-build --self-contained false -o dist/web
clean:
	dotnet clean "Dev1.sln"
	$(PYTHON) -c "from pathlib import Path; import shutil; root=Path.cwd().resolve(); p=(root/'dist').resolve(); assert p.parent == root and p.name == 'dist'; shutil.rmtree(p) if p.exists() else None"
