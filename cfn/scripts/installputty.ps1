Invoke-WebRequest "https://the.earth.li/~sgtatham/putty/0.74/w64/putty-64bit-0.74-installer.msi" -OutFile c:\putty.msi; 
Start-Process msiexec.exe -ArgumentList '/i c:\putty.msi /q' -Verb RunAs -Wait;
Remove-Item c:\putty.msi
New-Item -ItemType SymbolicLink -Path 'C:\Users\Administrator\Desktop\' -name 'Putty' -Value 'C:\Program Files\PuTTY\putty.exe'
reg import c:\putty.reg
