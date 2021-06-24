
Utils-Product-Engineering
-------------------------
This is the first version of UtilsNG, a collection of utilities and APIs and provides a simple interface over multiple 
system operations. Currently, the main purpose is to be used as wrapper for interaction with Atlassian API.
This can be achieved by instantiating one of the three designated classes:
JiraUtils, BitbucketUtils or BambooUtils by specifying the project key, the username and the password, which needs to be
sent base64 encoded.

Installation
------------
To install this package you can add it to your `requirements.txt` on your
project of by simply executing the standard `pip` command.

```shell script
pip install Utils-Product-Engineering
```

Usage
-----

from nxp.sw.amp.pe.utils.interface.atlassian import BitbucketUtils
bb = BitbucketUtils("artd", "SVC_DEVTECH", "{base64_encoded_password")
tag = bb.bitbucket_get_tag("adc", "refs/tags/BLN_TEST_TOOLBOX_2.0.6")

Contributing
------------
Contributions to this package are welcome, but they need to be checked for
quality since this package is base to many projects.

Please create your fork and branch in Bitbucket to develop your contribution. 
When it is ready submit a _Pull request_ against this repository master
branch and keep the review process alive by answering the reviews you may
receive.

For any further question you can contact any of the authors and maintainers
of the project.
