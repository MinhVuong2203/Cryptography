# ===== Build stage =====
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY . .

# đi vào đúng thư mục project
WORKDIR /src/Cryptography

RUN dotnet restore
RUN dotnet publish -c Release -o /app/publish

# ===== Runtime stage =====
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app

# Railway sẽ inject PORT
ENV ASPNETCORE_URLS=http://+:${PORT}

COPY --from=build /app/publish .

ENTRYPOINT ["dotnet", "Cryptography.dll"]