# Base image with Java (required for Ghidra)
FROM gradle:jdk17

# Setze Arbeitsverzeichnis
WORKDIR /app


RUN apt-get update && \
    apt-get install -y python3-pip

# Kopiere das gesamte Projektverzeichnis
COPY . .
# Kopiere das Python-Projekt
COPY src/ ./src


RUN apt-get install -y python3-venv
RUN python3 -m venv /venv
ENV PYTHONPATH /app
ENV PATH="/venv/bin:$PATH"

# Installiere das Python-Package
RUN pip install --no-cache-dir .

# Update the list of packages
RUN apt-get update

# Install pre-requisite packages
RUN apt-get update && apt-get install -y apt-transport-https software-properties-common

# Set .NET SDK urls
RUN if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        echo "DOTNET_URL=https://download.visualstudio.microsoft.com/download/pr/ca6cd525-677e-4d3a-b66c-11348a6f920a/ec395f498f89d0ca4d67d903892af82d/dotnet-sdk-8.0.403-linux-x64.tar.gz" >> /etc/environment; \
        echo "DOTNET_URL6=https://download.visualstudio.microsoft.com/download/pr/12ee34e8-640c-400e-a6dc-4892b442df92/81d40fc98a5bbbfbafa4cc1ab86d6288/dotnet-sdk-6.0.427-linux-x64.tar.gz" >> /etc/environment; \
    elif [ "$(dpkg --print-architecture)" = "arm64" ]; then \
        echo "DOTNET_URL=https://download.visualstudio.microsoft.com/download/pr/853490db-6fd3-4c17-ad8e-9dbb61261252/3d36d7d5b861bbb219aa1a66af6e6fd2/dotnet-sdk-8.0.403-linux-arm64.tar.gz" >> /etc/environment; \
        echo "DOTNET_URL6=https://download.visualstudio.microsoft.com/download/pr/30d99992-ae6a-45b8-a8b3-560d2e587ea8/a35304fce1d8a6f5c76a2ccd8da9d431/dotnet-sdk-6.0.427-linux-arm64.tar.gz" >> /etc/environment; \
    else \
        echo "Unsupported architecture: $(dpkg --print-architecture)"; exit 1; \
    fi


#RUN . /etc/environment && echo $DOTNET_URL

# Install Powershell for the appropriate architecture
RUN if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        # Download and install PowerShell for amd64
        wget https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/powershell-lts_7.4.6-1.deb_amd64.deb -O /tmp/powershell.deb && \
        dpkg -i /tmp/powershell.deb || apt-get install -f -y && \
        rm /tmp/powershell.deb; \
    elif [ "$(dpkg --print-architecture)" = "arm64" ]; then \
        # Download and install PowerShell for arm64
        apt-get install -y libc6 libgcc1 libgcc-s1 libgssapi-krb5-2 libicu70 liblttng-ust1 libssl-dev libssl3 libstdc++6 libunwind8 zlib1g curl && \
        curl -L -o /tmp/powershell.tar.gz https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/powershell-7.4.6-linux-arm64.tar.gz && \
        mkdir -p /opt/microsoft/powershell/7 && \
        tar zxf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7 && \
        chmod +x /opt/microsoft/powershell/7/pwsh && \
        ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh && \
        rm /tmp/powershell.tar.gz; \
    else \
        echo "Unsupported architecture: $ARCH"; exit 1; \
    fi


# Installiere retire, SecurityCodeScan, OWASP Dependency-Check, ILSpy, CFR und JADX
RUN . /etc/environment && \
    apt-get update && \
    apt-get install -y curl wget unzip mono-complete && \
    # Installiere Node.js und npm
    curl -fsSL https://deb.nodesource.com/setup_16.x | bash - && \
    apt-get install -y nodejs && \
    # Install retire
    npm install -g retire && \
    # Install OWASP Dependency-Check
    wget https://github.com/jeremylong/DependencyCheck/releases/download/v8.1.2/dependency-check-8.1.2-release.zip -O /tmp/dependency-check.zip && \
    unzip /tmp/dependency-check.zip -d /opt && \
    ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check && \
    # Install CFR
    wget https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar -O /opt/cfr.jar && \
    echo '#!/bin/bash\njava -jar /opt/cfr.jar "$@"' > /usr/local/bin/cfr && chmod +x /usr/local/bin/cfr && \
    # Install JADX
    wget https://github.com/skylot/jadx/releases/download/v1.4.6/jadx-1.4.6.zip -O /tmp/jadx.zip && \
    unzip /tmp/jadx.zip -d /opt/jadx && \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx
    
# Download and install .NET 8.0 SDK
RUN . /etc/environment && \
    wget $DOTNET_URL -O /tmp/dotnet-sdk.tar.gz && \
    mkdir -p /usr/share/dotnet && \
    tar zxf /tmp/dotnet-sdk.tar.gz -C /usr/share/dotnet && \
    ln -s /usr/share/dotnet/dotnet /usr/bin/dotnet

# Download and install .NET 6.0 SDK
RUN . /etc/environment && \
    wget $DOTNET_URL6 -O /tmp/dotnet6-sdk.tar.gz && \
    tar zxf /tmp/dotnet6-sdk.tar.gz -C /usr/share/dotnet
    

# Set environment variables for .NET 8.0
ENV DOTNET_ROOT=/usr/share/dotnet
ENV PATH=$PATH:/usr/share/dotnet:/usr/share/dotnet/tools


# Create the tools directory and set permissions
RUN mkdir -p /usr/share/dotnet/tools/ && \
    chmod -R 777 /usr/share/dotnet/tools


# Install ILSpy
RUN git clone https://github.com/icsharpcode/ILSpy.git /opt/ilspy && \
    cd /opt/ilspy && \
    git submodule update --init --recursive && \
    dotnet publish ICSharpCode.ILSpyCmd/ICSharpCode.ILSpyCmd.csproj -c Release -f net8.0 -o /opt/ilspy/ILSpyCmd/publish && \
    echo '#!/bin/bash\nexec dotnet /opt/ilspy/ILSpyCmd/publish/ilspycmd.dll "$@"' > /usr/local/bin/ilspycmd && \
    chmod +x /usr/local/bin/ilspycmd

# Install SecurityCodeScan as a global .NET tool
RUN dotnet tool install --global security-scan 



# Aufräumen
RUN rm -rf /var/lib/apt/lists/* /tmp/*

# Stelle sicher, dass Dotnet Tools ausführbar sind
ENV PATH="${PATH}:/root/.dotnet/tools"

# Setze den Startbefehl zum Starten des Python-Projekts
ENTRYPOINT ["dexray-insight"]