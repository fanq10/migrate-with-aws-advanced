Invoke-WebRequest "https://www.python.org/ftp/python/3.7.6/python-3.7.6.exe" -OutFile c:\python.exe; Start-Process c:\python.exe -ArgumentList '/quiet' -Verb RunAs -Wait; 
Remove-Item c:\python.exe 
[Environment]::SetEnvironmentVariable ;("C:\Users\Administrator\AppData\Local\Programs\Python\Python37-32\", $env:Path, [System.EnvironmentVariableTarget]::Machine)
[Environment]::SetEnvironmentVariable ;("C:\Users\Administrator\AppData\Local\Programs\Python\Python37-32\Scripts\", $env:Path, [System.EnvironmentVariableTarget]::Machine) 
py.exe -m pip install --upgrade pip 
py.exe -m pip install requests 
py.exe -m pip install paramiko 
py.exe -m pip install boto3 
