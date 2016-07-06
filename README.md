##pam_gate
pam_gate is pam authentication module for gate-sso project. It's heavily inspired by pam-http from Kragen Sitaker and then we forked it from https://github.com/beatgammit/pam-http Jameson Little's repo but since it diverged so much in terms of functionlity and also it started moving towards different curl based password authentication - then we just moved it into new repo, since there is no way this will be going back there. Most probably original repo's functions are still there but they are heavily modified.

--

####Configuration

pam_gate is pam authentication module, we can simply put it inside one of the files in `/etc/pam.d/` 
Most of the time `/etc/pam.d/common-auth` is the right place to put it. With following configuration

        auth sufficient pam_gate.so url=<gate-sso-host>/profile/authenticate_pam
        account sufficient pam_gate.so

You also need to put `pam_gate.so` file to appropriate place, I am looking for someone to create packages, but in absense of that in Ubuntu this should goto `/lib/*/security` or `/usr/lib/security` in some distros, if you can't figure it out, please create an issue, we will be able help you setup this.

Soon you should be able to get a package and automated deploy scripts.


Old Intro
=====

The old and original intro

"This module is heavily inspired by the pam-http module by Kragen Sitaker. I rewrote it largely because I wanted to MIT license it (instead of GPL) and because there was some profanity in the source.  Also, the version I modeled this off of didn't even compile because it used an old version of libcurl."

I forked it from https://github.com/beatgammit/pam-http Jameson Little's repo, but this gone into multuple changes.

So now what it does is something simple.

Expects a URL

        auth sufficient gate_pam.so url=https://<URL>?user=<username>=password=<password>
        account sufficient gate_pam.so

Since I user google authenticator as password, that's why I did not care about obsfucating the password, but if you want to authenticate against your own DB, then you might want to make that change.


Simple Usage
------------

The .so file should be put in `/lib/*/security` and the PAM config files will need to be edited accordingly.

The config files are located in `/etc/pam.d/` and the one I changed was `/etc/pam.d/common-auth`. i
This is NOT the best place to put it, as sudo uses this file and you could get unexpected results. But if you have any other suggestions please let me know.


	auth sufficient mypam.so url=https://localhost:2000
	account sufficient mypam.so

Sufficient basically means that if this authentication method succeeds, the user is given access.

Contributor: Ajey Gore 


