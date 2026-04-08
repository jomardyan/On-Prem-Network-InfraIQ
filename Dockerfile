# On-Prem Network InfraIQ - Professional Docker Image
LABEL name="On-Prem Network InfraIQ" 
      version="2.1.0" 
      description="Enterprise-grade network discovery and security assessment platform" 
      maintainer="On-Prem Network InfraIQ Team" \cr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 5000
EXPOSE 5001

# Install network utilities for enhanced scanning capabilities
RUN apt-get update && apt-get install -y \
    iputils-ping \
    traceroute \
    nmap \
    dnsutils \
    net-tools \
    curl \
    wget \
    tcpdump \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["Discovery/Discovery.csproj", "Discovery/"]
COPY ["Discovery.Tests/Discovery.Tests.csproj", "Discovery.Tests/"]
RUN dotnet restore "Discovery/Discovery.csproj"
COPY . .
WORKDIR "/src/Discovery"
RUN dotnet build "Discovery.csproj" -c Release -o /app/build

FROM build AS test
WORKDIR /src
RUN dotnet test "Discovery.Tests/Discovery.Tests.csproj" --no-build --verbosity normal

FROM build AS publish
RUN dotnet publish "Discovery.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

# Create app user for security
RUN useradd -r -g users -u 1001 appuser && \
    chown -R appuser:users /app
USER appuser

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Environment variables for professional deployment
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:5000;https://+:5001
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1

# Labels for container metadata
LABEL name="On-Prem Network InfraIQ" \
      version="2.1.0" \
      description="Enterprise-grade network discovery platform with web dashboard, database storage, IPv6 support, cloud integration, and ML anomaly detection" \
      maintainer="On-Prem Network InfraIQ Team" \
      vendor="Enterprise Security Solutions" \
      license="MIT"

ENTRYPOINT ["dotnet", "AdvNetDiscovery.dll"]