### ARC signer in Python
Repository for ARC signing in Python with virtualenv.


#### Setup
```
pip install --upgrade setuptools # upgrade setuptools
pip install -r requirements.txt
```

#### Gotchas:

The `dkimpy` library that is used internally won't include 
`dkim-signature` by default. After installing all the requirements, 
remove `dkim-signature` from the `SHOULD_NOT` tuple in the file. It'll
be typically located in the following file (~L516):
```
venv/lib/python3.7/site-packages/dkim/__init__.py
``` 

After modification, the `SHOULD_NOT` should look like the following:
```
#: The rfc6376 recommended header fields not to sign.
#: @since: 0.5
SHOULD_NOT = (
b'return-path',b'received',b'comments',b'keywords',b'bcc',b'resent-bcc'
)
``` 
