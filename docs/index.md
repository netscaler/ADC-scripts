# Citrix NetScaler Ansible Module Documentation

This project implements a set of Ansible modules for the Citrix NetScaler. Users of these modules can create, edit, update, and delete configuration objects on a NetScaler. For more information on the basic principals that the modules use, see the usage/index.

The code is licensed under the GPL and the authoritative repository is on github

The main documentation for the modules is organized into several sections listed below.

## User Documentation

* [Getting Started](./usage/getting-started.md)
    * Installing Ansible
    * Installing Modules
    * Playbook
* [Speeding up execution](./usage/speeding-up-execution.md)
    * Saving configuration
    * Sample playbook
    * Closing remarks
* [Rolling upgrades](./usage/rolling-upgrades.md)
    * Setup
    * Testbed
    * Upgrade process
    * References
* [Rolling upgrades (VPX)](./usage/rolling-upgrades-vpx.md)
    * Setup
    * Initializing the testbed
    * Upgrade process
    * References
* [NetScaler ansible docker image](./usage/docker-image.md)
    * Installation
    * Usage
    * Example

## Using generic ansible modules

* [Using generic Ansible modules](./generic-modules/about.md)
    * References
* [Templating the configuration file](./generic-modules/templating-configuration-file.md)
    * Workflow
    * Playbook
    * References
* [Direct NITRO API calls](./generic-modules/nitro-api-calls.md)
    * Workflow
    * Playbook
    * References

## Module Documentation

* [Module Index](./modules/index.md)

## Developer Documentation

* [Development Utilities](./development-utilities.md)
    * Developing a new module
    * Getting the spec of a nitro object
    * Generating the boilerplate
