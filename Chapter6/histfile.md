# The history file on Linux
The following are some basic commands to drop or enhance the bash history file on Linux
## Enhancing the bash history
This one liner will set a new location for the bash history of any new user:
```
# echo 'HISTFILE=/var/log/user_history' >> /etc/skel/.bashrc
```
This one liner will add timestamps to the bash history of any new user:
```
# echo 'HISTTIMEFORMAT="%d/%m/%y %T"' >> /etc/skel/.bashrc
```
## Tampering with bash history
You can stop the bash history for the active user by running:
```
$ unset HISTFILE
```
You can also clear the bash history for the active user with:
```
$ history -c
```
You can set it so a particular user you use never has a bash history with:
```
$ echo "unset HISTFILE" >> ~/.bash_profile; echo "unset HISTFILE" >> ~/.bashrc;
```
Or you can have the bash history clear every time a user logs out:
```
$ echo 'history -c' >> ~/.bash_logout
```
Finally, you can leave the bash history in tact but have it not log commands with leading spaces:
```
$ HISTCONTROL=ignoredups:ignorespace
```
