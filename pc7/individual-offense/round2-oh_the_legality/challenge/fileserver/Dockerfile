# ---- build stage (Ubuntu base + SDK) ----
    FROM ubuntu:22.04 AS build

    # Base build deps + .NET SDK
    RUN apt-get update \
      && DEBIAN_FRONTEND=noninteractive apt-get install -y \
         ca-certificates \
         dotnet-sdk-8.0 \
         wget \
         apt-transport-https \
         gnupg \
      && rm -rf /var/lib/apt/lists/*
    
    # Install PowerShell (pwsh) in build stage (optional, but fine if you want it here too)
    RUN wget -q https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb \
        && dpkg -i packages-microsoft-prod.deb \
        && rm packages-microsoft-prod.deb \
        && apt-get update \
        && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends powershell \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*
    
    # Stop “first time experience” / telemetry during build
    ENV DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
        DOTNET_CLI_TELEMETRY_OPTOUT=1 \
        DOTNET_NOLOGO=1 \
        NUGET_XMLDOC_MODE=skip
    
    WORKDIR /src
    
    # Create project and copy your Program.cs
    RUN dotnet new console -n Server
    COPY app.cs /src/Server/Program.cs
    
    WORKDIR /src/Server
    
    # Build/publish so runtime never restores/builds (no internet needed at runtime)
    RUN dotnet restore --disable-parallel
    RUN dotnet publish -c Release -o /out --no-restore
    
    
    # ---- runtime stage (Ubuntu base + runtime only) ----
    FROM ubuntu:22.04
    
    # Install runtime packages + prereqs for PowerShell repo
    RUN apt-get update \
      && DEBIAN_FRONTEND=noninteractive apt-get install -y \
         apache2 \
         dotnet-runtime-8.0 \
         openssh-server \
         iproute2 \
         inetutils-ping \
         curl \
         host \
         mtr-tiny \
         tcpdump \
         iptables \
         wget \
         apt-transport-https \
         ca-certificates \
         gnupg \
      && rm -rf /var/lib/apt/lists/*
    
    # Install PowerShell (pwsh) in runtime stage (this is what fixes "pwsh: command not found")
    RUN wget -q https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb \
        && dpkg -i packages-microsoft-prod.deb \
        && rm packages-microsoft-prod.deb \
        && apt-get update \
        && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends powershell \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*
    
    # Your files
    COPY secret.pdf /root/secret.pdf
    
    # Copy published output from build stage
    WORKDIR /app
    COPY --from=build /out/ ./
    
    # Optional entrypoint script (if you want to start apache/sshd/etc)
    COPY entrypoint.sh /app/entrypoint.sh
    RUN chmod +x /app/entrypoint.sh
    
    # Hard-disable anything “first time” / telemetry / nuget-y at runtime
    ENV DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
        DOTNET_CLI_TELEMETRY_OPTOUT=1 \
        DOTNET_NOLOGO=1 \
        NUGET_XMLDOC_MODE=skip \
        DOTNET_CLI_HOME=/tmp
    
    # Run the already-published app (no restore/build, no internet)
    #CMD ["./Server"]
    CMD ["/app/entrypoint.sh"]
    