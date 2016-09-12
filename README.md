# aws audit tool
AWS account audit tool - written into various lambda functions

sudo-code:

set variable for time account password has been inactive (time - last used) (variable A)
set variable for time key can be active (time - creation date) (Variable B)

get user list

determine if password is set on account
  - if last time utilized is over (variable A) add to list

get list of keys per user (0-2)
  - get creation date on all keys
  - if creation date was over (Variable B) add to list

Create email with list of:
  - users with outdated passwords (username, password age)
  - users with outdated keys (username, key, key age)
