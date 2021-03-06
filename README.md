# pam_http
PAM service module implementation using HTTP call

## Usage
This module currently implements the account and session stacks. To use it, include the following line in your appropriate pam configuration file:  
`account        required        /path/to/pam_http.so    uri=https://www.example.com/?user=%u&host=%h&service=%s&type=%t`  
`session        required        /path/to/pam_http.so    uri=https://www.example.com/?user=%u&host=%h&service=%s&type=%t`

### Arguments
Argument | Description
:--------|:-----------
debug    | Turns debugging on. Output to stderr of whatever program is calling the PAM stack.
timeout  | Specify the number of seconds to wait for return before failing. Defaults to 30 seconds.
uri      | Location to call. Returns success if it is an HTTP 200 response code. All other response codes are considered errors.

The `uri` argument supports the following string substitutions:
Code | Replacement
:----|:-----------
`%%` | A literal `%`.
`%h` | The current hostname of the host making the outbound call.
`%s` | The PAM service. Example: `ssh`
`%t` | The call type. Will be one of `account`, `open_session`, or `close_session`.
`%u` | The username of the user the PAM stack is executing on behalf of. Note, this user must exist in the password file (rather, `getpwnam` must succeed).

## Build
The build should work correctly on OpenPAM and Linux-PAM stacks. More testing has occurred on FreeBSD with OpenPAM.
```
# make
# make install
```
By default, I've included Makefiles for bmake (using the FreeBSD build structure) and gmake. The compiled module will install into `/usr/local/lib/pam_http.so`. If you desire it to be elsewhere, just copy to wherever you want it and update your `pam.conf` configuration to point to it.

On CentOS 7, I had to install `gcc`, `pam-devel`, and `libcurl-devel` to get it to compile.
On Ubuntu 20.10, I had to install `gcc`, `libpam0g-dev`, and `libcurl4-openssl-dev` to get it to compile.

I found `pamtester` (available on FreeBSD and Ubuntu) to be very helpful in testing.
