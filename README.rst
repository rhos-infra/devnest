# Devnest Tool

A simple CLI to manage "reservations" for the hardware in devnest.

The primary use case for this tool is to reserve shared node
for debugging and development work.

Current implementation uses Jenkins APIs and metadata stored inside
Jenkins to manage lifecycle of hardware in the DevNest.

Once the node is reserved it's being put offline, so no other Jenkins
user is able to use it, until reservation expires and it's being cleaned.

### Usage

## Config File

By default, devnest looks for ~/.config/jenkins_jobs/jenkins_jobs.ini,
or /etc/jenkins_jobs/jenkins_jobs.ini (in that order).

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

## Run DevNest CLI

Running in virtual environment:

```
git clone https://github.com/rhos-infra/devnest.git
virtualenv my-devnest-virtenv
source my-devnest-virtenv/bin/activate
pushd devnest
pip install .
devnest --help
```

## Sample commands

To list based on regexp in a "shared" pool of servers
```
devnest --conf config.ini list -g shared "*my_node_0?"
```

To list all i a "shared" pool of servers
```
devnest --conf config.ini list -g shared
```

To reserve node from "shared" pool for 4h (regex must match only 1 node)
```
devnest --conf config.ini reserve -g shared -t 4 *my_node_03
```

To release reservation
```
devnest --conf config.ini release *my_node_03
```
