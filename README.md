## README

This is a *super* basic Rails app designed to be used to test SAML clients.

It is based on gems and work by:

https://github.com/sportngin/saml_idp
https://github.com/lawrencepit/ruby-saml-idp

And largely (though not completely) follows the guide outlined here: https://github.com/sportngin/saml_idp/wiki

## Intended Use Case

This app is designed to be downloaded and run locally. Running:

```bash
git clone git@github.com:jacobsmith/dev_saml_provider.git
cd dev_saml_provider
rails server -p 3000
```

and then additional instances can be run with

```bash
rails server -p 3001
```

etc.

## Configuration

For convenience, there is a hosted version of this available at `https://supersimplesamlidp.herokuapp.com`

SAML requests will need to be sent to: `https://supersimplesamlidp.herokuapp.com/saml/auth`
The certificate fingerprint is: `9E:65:2E:03:06:8D:80:F2:86:C7:6C:77:A1:D9:14:97:0A:4D:F4:4D`

Obivously this is *SUPER INSECURE* so please only use it for dev or testing environments where you're not worried if data integrity is compromised. As soon as you need real authentication, do not use this, this is just for quick setup and testing of SAML configurations.

==
Locally
==

By default, setting up a SAML client to point to: `http://localhost:3000/saml/auth` should initiate the flow.

Currently, the SAML responses are as follows:

```ruby
{
  email: {
    name: "urn:oid:0.9.2342.19200300.100.1.3",
  },
  nickname: {
    getter: :name,
    name: "urn:oid:2.5.4.3"
  },
  user_id_attribute: {
    getter: :id,
    name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
  }
}
```

These can be easily changed in code if need be (and if other peple find it useful, a configuration could be added to further simplify the process).


At the login page, you can enter any email address, and it will be "valid" if the password is `password`.
The name that is returned is the local part of the email with `+`, `_`, and `.` replaced with spaces.
The `user_id_attribute` is a MD5 digest of the email address, so each login with the *same* email address should return the same ID, mimicing multiple persisted users.

## Security

There is none. This is the opposite of secure. It uses default security certificates shipped with the `saml_idp` gem, which are publicly available on GitHub. Furthermore, this has 0 testing around it, nor do I have much knowledge in terms of supporting SAML IdP in a production setting. This is *only* meant to be a simple, easy to setup endpoint that echoes back some SAML for testing clients. You have been warned.
