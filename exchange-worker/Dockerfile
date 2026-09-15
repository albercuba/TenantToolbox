FROM mcr.microsoft.com/powershell:7.4-debian-12

RUN pwsh -NoLogo -NoProfile -NonInteractive -Command "Install-Module ExchangeOnlineManagement -Scope AllUsers -Force -AllowClobber"
WORKDIR /worker
COPY worker.ps1 /worker/worker.ps1
EXPOSE 8080
ENTRYPOINT ["pwsh", "-NoLogo", "-File", "/worker/worker.ps1"]
