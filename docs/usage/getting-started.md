# Getting Started

This document will show you how to begin using the NetScaler Ansible modules.

First, obtain [Python 2.7](http://www.python.org/) and [Ansible](http://docs.ansible.com/ansible/intro_installation.html) if you do not already have them.

The version of Ansible that is required is at least 2.4.0.

## Installing Ansible


Installing Ansible may be accomplished through the following methods.

Further documentation on installing Ansible  may be found in [github](https://github.com/ansible/ansible)

### Using pip

```bash
pip install ansible
```

### Using your package manager

E.g. in a Debian based Linux distribution

```bash
apt-get install ansible
```

### Using a direct checkout

```bash
git clone https://github.com/ansible/ansible
   
cd ansible

source hacking/env-setup
```

### Verifying the installation

Following any installation method you should be able to run the following code which will print out the ansible version you will be using

```bash
ansible --version
```


## Installing Modules

To install the latest version of the NetScaler modules run the following commands

```bash
git clone https://github.com/citrix/netscaler-ansible-modules
   
cd netscaler-ansible-modules
   
python install.py
```

The install script will detect where the ansible library is installed and will try to copy the module files to the appropriate directories.

!!!tip "Note"
		The last step may require root priviledges depending on where ansible is installed.



## Playbook

Last we are going to see how to make a simple playbook. 

```yaml

   - name: Create a server
       delegate_to: localhost
       gather_facts: no

       netscaler_server:
           nsip: 172.18.0.2
           nitro_user: nsroot
           nitro_pass: nsroot

           state: present

           name: test-server-1
           ipaddress: 192.168.1.1

```