![Citrix Logo](media/Citrix_Logo_Trademark.png)

# Citrix ADC scripts for migrating and converting Citrix ADC configuration with deprecated features

## Description

When you migrate from a Citrix ADC version with deprecated features, you may lose some of the configuration. Citrix provides you scripts to avoid such configuration loss when you are migrating from an old version with deprecated features to the newer version. 

This repository contains the following scripts:

- [`tdToPartition.pl`](td-to-ap/tdToPartition.pl): The script for migrating the traffic domain configuration on a Citrix ADC to the admin partition configuration. For more information on how to use the script, see [Migrating traffic domain configuration on a Citrix ADC to admin partition configuration](td-to-ap/migration-script-td.md).

- [`check_invalid_config`](nspepi/check_invalid_config): Pre-validation script to check if any deprecated functionality that is removed from Citrix ADC release version 13.1 is still used in the configuration. For more information on how to use the script, see [Scripts for pre-validating and converting deprecated features](nspepi/validation-conversion-script.md).

- [`NSPEPI`](nspepi/nspepi): The script that converts deprecated commands or features to non-deprecated commands or features. For more information on how to use the script, see [Scripts for pre-validating and converting deprecated features](nspepi/validation-conversion-script.md).


## <a name="questions">Questions</a>

For questions and support, the following channels are available:

-  [Citrix Discussion Forum](https://discussions.citrix.com/)


## <a name="licensing">Licensing</a>

The Citrix ADC scripts are licensed with [CITRIX TOOL LICENSE](LICENSE.md).