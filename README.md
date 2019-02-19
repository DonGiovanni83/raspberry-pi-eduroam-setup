# Headless eduroam setup

This installer connects your device to an eduroam network.

Some functions are taken from the official [eduroam linux installer](https://cat.eduroam.org/).

## How it works

 1. Create a file named _rapberry-config_ containing following information:
```
EDUROAM_USER = username@UNIBERN.ch

EDUROAM_PWD = userpasswd

USER_EMAIL = useremail@hotgmail.ch

```
 2. Set those environment variables:
    Set the path to where your _rapberry-config_ is locatet:
    - `CONFIG_FILE_PATH="~/path/to/config"`
    
    Those variables are needed for the email configuration to work
    - `EMAIL_SERVER="your.smtp.server.ch"`
    - `EAMIL_PORT="465"`
    - `EMAIL_LOGIN="your.server.login@myemail.ch"`
    - `EMAIL_PWD="yourpassword"`
    - `EMAIL_FROM="MyEmail <sender.email@myemail.ch>"`

 3. Execute the installer with `python eduroam-setup.py`
