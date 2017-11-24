# Jenkins Node Tool

A simple CLI to manage "reservations" for the nodes.

The primary use case for this tool is to reserve Jenkins node
for debugging and development work.

Once the node is reserved it's being put offline, so no other Jenkins
user is able to use it, until reservation expires and it's being cleaned.

### Usage

## Config File

It is possible to replace CLI arguments such as user, password and url
with config file containing this information and pass path to this file
using --conf flag.:

```
[jenkins]
user=JENKINS_USERNAME
password=JENKINS_API_TOKEN
url=https://JENKINS_URL
```

JENKINS_API_TOKEN can be found using Jenkins at:
    https://JENKINS_URL/user/JENKINS_USERNAME/configure

## Run Jenkins Node CLI

Running in virtual environment:

```
git clone https://github.com/mpryc/jenkins-node-tool.git
virtualenv my-jenkins-node-tool-virtenv
source my-jenkins-node-tool-virtenv/bin/activate
pushd jenkins-node-tool
pip install .
jenkinsnodecli --help
```

## Sample commands

To list based on regexp
```
jenkinsnodecli --conf config.ini -l *my_node_0?
```

To list all
```
jenkinsnodecli --conf config.ini -l
```

To reserve node for 4h (regex must match only 1 node)
```
jenkinsnodecli --conf config.ini -r 4 *my_node_03
```

To clear reservation
```
jenkinsnodecli --conf config.ini -c *my_node_03
```
