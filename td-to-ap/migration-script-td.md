# Migrating traffic domain configuration on a Citrix ADC to admin partition configuration using the tdToPartition.pl script

Citrix ADC provides different options to create multiple isolated environments within a same Citrix ADC appliance such as traffic domains and admin partitions. Admin partitions provide much better control and management than traffic domains. 

You can migrate the traffic domain configuration on a Citrix ADC to the admin partition configuration using the `tdToPartition.pl` script provided by Citrix.


## Running the script

Download the `tdToPartition.pl` using below command:

        wget https://raw.githubusercontent.com/citrix/ADC-scripts/master/td-to-ap/tdToPartition.pl


The following commands show the usage of the script.
	#./tdToPartition.pl

        perl tdToPartition.pl <TD-PartName_mapping_file> <input_config_file> <output_config_file>

The parameters you need to provide are explained as follows:

- `TD-PartName_mapping_file` - This file is the traffic domain to admin partition name mapping input file that needs to be done by the customer.


- `input_config_file` - This file is the existing traffic domain deployment configuration input file (`ns.conf`) for Citrix ADC

- `output_config_file` - This file is the newly generated output file (`td_migration_ap.conf`) after running the migration script on input files (`ns.conf` and `TD-PartName_mapping_file`).


The following example shows the content of a sample `TD-PartName_mapping_file` named `map.csv`.

        # cat map.csv
            256|ap_256
            1150|ap_1150
            206|ap_206
            247|ap_247
            253|ap_253
            32|ap_32
            702|ap_702

The contents of the files are in the `TD-name` | `admin-partition-name`  format.


During the run of the migration tool script, corresponding to each admin partition `ns.conf` file, the respective log file is generated. You can apply this newly generated output file (`td_migration_ap.conf`) using the ``batch -fileName <input_filename>``  command from the Citrix ADC CLI. 

**Note**
You must verify and ensure that there is no loss of configuration during the migration.


Following is the content of a sample `td_migration_ap.conf` file.

       # cat td_migration_ap.conf

        rm trafficDomain 1
        add ns partition Partition-SECURE
        bind ns partition Partition-SECURE -vlan 40
        switch partition Partition-SECURE
        batch -filename /var/td_migration_ap.conf.Partition-SECURE.conf -outfile /var/td_migration_ap.conf.Partition-SECURE.out
        save config
        switch partition DEFAULT
        save config 



## Specific deployment scenarios and changes

Based on how the configured VLANs are associated to traffic domains in the existing deployment, the following two scenarios need to be addressed while migrating from traffic domains to admin partitions. 

-  Tagged VLANs bound to a traffic domain: This deployment works as per the steps mentioned in stand-alone and HA deployment scenarios.

-  Untagged VLANs bound to a traffic domain: For this scenario, you need to consider the following two options depending upon their existing deployment and need to consider the following explicit configuration before applying the configuration generated from the migration script so that the partition VLAN binding does not fail.

    - IP addresses are overlapping: You need to change the untagged VLAN configuration to the tagged VLAN configuration. IP address overlapping is supported with dedicated VLANs (tagged VLANs) for admin partitions.
    
    - IP addresses are non-overlapping or existing untagged VLAN cannot be configured as tagged:
      You need to make the untagged VLAN as shared VLAN because only the untagged shared VLAN can be bound to the admin partition since the introduction of the shared VLAN feature for admin partition. From Citrix ADC release version 11.1, IP address overlapping is not supported with shared VLAN for admin partitions because the shared VLAN can be bound for more than one partition.

### Untagged VLANs:  overlapping IP addresses deployment scenario

In this scenario, the traffic domain configuration contains untagged VLANs and it is converted to the admin partition configuration.

Following is a sample traffic domain configuration for migration.

        add vlan 102 
        bind vlan 101 -ifnum 1/2
        bind vlan 102 -ifnum 1/3
        bind ns trafficDomain 101 -vlan 101
        bind ns trafficDomain 102 -vlan 102


 To avoid errors, you must change the configuration in the `ns.conf` file before running the migration script:
 
        bind vlan 101 -ifnum 1/2  -tagged 
        bind vlan 101 -ifnum 1/3  -tagged 

After running the migration script on the `ns.conf` file, the following is the admin partition configuration:


        rm trafficDomain 102
        rm trafficDomain 101
        add ns partition "INSIDE2"
        add ns partition "INSIDE"
        bind ns partition "INSIDE" -vlan 101
        bind ns partition "INSIDE2" -vlan 102


You may see the following errors if you do not change the configuration in the `ns.conf` file.

        > bind ns partition "INSIDE" -vlan 101
        ERROR: The specified VLAN cannot be bound to a partition because it is configured as untagged member of interface.

        > bind ns partition "INSIDE2" -vlan 102
        ERROR: The specified VLAN cannot be bound to a partition because it is configured as untagged member of interface.

###  Untagged VLANs: non-overlapping IP addresses deployment scenario

Following is a sample traffic domain configuration for migration.

        add ns trafficDomain 101 
        add ns trafficDomain 102 
        add vlan 101 
        add vlan 102 
        bind vlan 101 -ifnum 1/2
        bind vlan 102 -ifnum 1/3
        bind ns trafficDomain 101 -vlan 101
        bind ns trafficDomain 102 -vlan 102

You should add the following configuration in the migration configuration file before running the migration script:

        set vlan 101 -sharing ENABLED
        set vlan 102 -sharing ENABLED

After running the migration script on the `ns.conf` configuration, the following is the admin partition configuration:


        rm trafficDomain 102
        rm trafficDomain 101
        add ns partition "INSIDE2"
        add ns partition "INSIDE"
        bind ns partition "INSIDE" -vlan 101
        bind ns partition "INSIDE2" -vlan 102



You may see the following errors if the migration configuration file is not modified before running the migration script:


    > bind ns partition "INSIDE" -vlan 101
    ERROR: The specified VLAN cannot be bound to a partition because it is configured as untagged member of interface.
    > bind ns partition "INSIDE2" -vlan 102
    ERROR: The specified VLAN cannot be bound to a partition because it is configured as untagged member of interface.


### Cross-traffic domain binding configurations

If you are using cross traffic domain binding or referencing across traffic domains, it is allowed only for virtual server service binding (that means `vserver` in the default traffic domain and service in another traffic domain). Before applying the migration script on the existing `ns.conf` file, you should take care of the cross traffic domain binding.

**Note:** Cross traffic domain configuration is not allowed across admin partitions. 

## Detailed migration steps 

Following are the migration steps for stand-alone and high availability deployments.

### Stand-alone deployment

For stand-alone deployments, here are the details of migration steps:

1. Create the admin partition configuration first. You can use the migration script, which can help to pull the TD configuration and dependencies into a single file.

1. Add the admin partition. 
1. If the admin partition configuration refers any SSL certificates, then copy them to the `/var/partitions/<partition-name>/ssl` folder.
1. Batch the configuration inside the admin partition. When you perform this step, VLAN-specific configurations such as IP bindings may fail.
1. Verify if any configuration failed due to a configuration not being present in the admin partition. Then you need to include the missing configuration and retry.
1. Now, unbind all VLANs from the traffic domain and bind them to the admin partition. Apply the VLAN specific configuration inside the admin partition.

1. Check that all services are coming up properly. 

1. If any problem is seen, unbind the VLANs from the admin partition, bind them back to the traffic domain so that traffic domain configuration can become active again.

1. Otherwise, remove the traffic-domain. Save the configuration inside the admin partition.

### High availability

For high availability deployments, here are the details of migration steps:

1. Create the admin partition configuration first. You can use the migration script, which can help to pull the traffic domain configuration and dependencies in to a single file.

1. Disable high availability synchronization and propagation on both primary and secondary Citrix ADCs. (Use the `set ha node -hasync disABLED -haprop disabled` command.)
1.  In the secondary Citrix ADC, remove the traffic domain.
1. Add the admin partition. 
1. Bind to the admin partition.
1. If the admin partition configuration refers any SSL certificates, then copy them to the `/var/partitions/<partition-name>/ssl` folder.
1. Batch the configuration inside the admin partition.
1. Verify that if any configuration was failed due to a configuration not being present in the admin partition. Then you need to include the missing configuration and retry.
1. Perform a forced failover.
1. Verify that all services are coming up properly.
1. If there are any issues, perform the forced failover again.
1. Otherwise, enable high availability synchronization and propagation.

**Note:** Once the admin partitions are up, 10 MB is configured as the default memory for each partition. The memory of partitions can be changed according to your requirements.


