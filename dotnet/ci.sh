#!/bin/bash

set -e
cd Miscreant.Tests

dotnet restore
dotnet build
dotnet test