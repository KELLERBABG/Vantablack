@echo off
echo Adding Windows Firewall rule for Global Ghost Net Hub (UDP 55225)...
netsh advfirewall firewall add rule name="GGN Hub" dir=in action=allow protocol=UDP localport=55225
echo.
echo ========================================================
echo Firewall rule added successfully!
echo You can now connect from your phone.
echo ========================================================
pause
