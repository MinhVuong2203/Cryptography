# ===== Build stage =====
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# copy toàn bộ source
COPY . .

# restore + publish
RUN dotnet restore Cryptography.csproj
RUN dotnet publish Cryptography.csproj -c Release -o /app/publish

# ===== Runtime stage =====
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app

# Railway inject PORT -> phải dùng biến này
ENV ASPNETCORE_URLS=http://+:${PORT}

COPY --from=build /app/publish .

ENTRYPOINT ["dotnet", "Cryptography.dll"]