$ZIP_NAME="pin-3.20-98437-gf02b61307-msvc-windows"
$PREFIX = ${HOME}
Set-Location -Path ${HOME}

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri https://software.intel.com/sites/landingpage/pintool/downloads/${ZIP_NAME}.zip -OutFile ${PREFIX}\${ZIP_NAME}.zip
Expand-Archive -Force -Path ${PREFIX}\${ZIP_NAME}.zip -DestinationPath ${PREFIX}
Remove-Item ${PREFIX}\${ZIP_NAME}.zip

echo "Please set:"
echo "set PIN_ROOT=${PREFIX}\${ZIP_NAME}"