
Utils-Product-Engineering
-------------------------

This package provides a simple interface over multiple system operations.

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
bb = BitbucketUtils("artd")
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
