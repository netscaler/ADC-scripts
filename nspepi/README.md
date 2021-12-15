# Scripts for pre-validating and converting deprecated features

In Citrix ADC release version 13.1, some features and functionalities have been removed. If the current ADC configuration contains any of those features and functionalities, then that configuration would be lost after upgrading to 13.1. Before upgrading to 13.1, you must first convert the configuration to the Citrix recommended alternatives to avoid such loss of configurations. Citrix provides scripts to help you with the conversion.

The following features and functionalities have been removed in 13.1:

- Filter feature.
- Speedy (SPDY), sure connect (SC), priority queuing (PQ), HTTP denial of service (DoS), and HTML injection features.
- Classic policies for content switching, Cache redirection, compression, and application firewall.
- URL and domain parameters in the `add cs policy` command.
- Classic expressions in load balancing persistence rules.
- The `pattern` parameter in Rewrite actions.
- The  `bypassSafetyCheck` parameter in the Rewrite actions.
- `SYS.EVAL_CLASSIC_EXPR` in advanced expressions.
-  The `policy patClass` configuration entity.
- `HTTP.REQ.BODY` with no argument in advanced expressions.
- Q and S prefixes in the advanced expressions.
- The `policyType` parameter for the `cmp parameter `setting.

The following tools help with the conversion:

- Validation tool for detecting removed deprecated features and functionalities in Citrix ADC version 13.1.
- NSPEPI tool for converting deprecated commands/features to non-deprecated commands/features.

**Note:** Both the validation tool and the NSPEPI tool can be used only with Citrix ADC release version 12.1 or later.

For using the conversion tools, copy the files from here to your Citrix ADC appliance as per the instructions:

1. Clone the repo `https://github.com/citrix/ADC-scripts.git` and goto `ADC-scripts/nspepi` directory.
2. Copy `nspepi_install_script`, `nspepi`, and `check_invalid_config` files to the `/netscaler` path in Citrix ADC.
3. Copy all files under the `nspepi2` directory to the `/netscaler/nspepi2` path in Citrix ADC.
4. After copying files to Citrix ADC, change your directory to `/netscaler` and then run the `bash nspepi_install_script` command.

## Pre-validation tool for removed or deprecated features in Citrix ADC version 13.1

This is a pre-validation tool to check if any deprecated functionality that is removed from Citrix ADC 13.1 is still used in the configuration for your current release. If the validation result shows usage of a deprecated functionality, then before upgrading your appliance, you must first modify the configuration to the Citrix recommended alternative. You can modify the configuration either manually or using the NSPEPI tool.

### Running the validation tool:

This tool needs to be run from the command line of the shell within the Citrix ADC appliance (you need to type the `shell` command on the Citrix ADC CLI).

        check_invalid_config <config_file>
    

The `config_file` parameter: The configuration file that needs to be checked and it should be from a saved configuration, such as in the `ns.conf` file. 

### Examples:

The following example shows when the configuration file contains deprecated functionality that is removed from Citrix ADC 13.1.

        # check_invalid_config /nsconfig/ns.conf

        The following configuration lines get errors in 13.1 and these configurations and also any dependent configuration is removed from the configuration:
        add policy expression x "sys.eval_classic_expr(\"ns_true\")"
        add cmp policy cmp_pol -rule ns_true -resAction GZIP
        add cs policy cs_pol_2 -rule ns_trueadd cs policy cs_pol_3 -domain www.abc.com
        add cs policy cs_pol_4 -url "/abc"
        add rewrite action act_1 replace_all "http.req.body(1000)" http.req.url -pattern abcd
        add rewrite action act_123 replace_all http.req.url "\"aaaa\"" -pattern abcd
        add responder action ract respondwith "Q.URL + Q.HEADER(\"abcd\")"
        add responder policy rsp_pol "sys.eval_classic_expr(\"ns_true\")" DROP
        add appfw policy aff_pol_1 "http.req.body.length.gt(10)" APPFW_BYPASS
        add appfw policy aff_pol ns_true APPFW_BYPASS

        The nspepi upgrade tool can be useful in converting your configuration. For more information, see the documentation at https://docs.citrix.com/en-us/citrix-adc/current-release/appexpert/policies-and-expressions/introduction-to-policies-and-exp/converting-policy-expressions-nspepi-tool.html.


The following is an example when the configuration file does not contain any deprecated functionality that is removed from Citrix ADC 13.1.

    # check_invalid_config /var/tmp/new_ns.conf

    No issue detected with the configuration.

## NSPEPI tool

The `NSPEPI` tool helps in converting the deprecated commands or features to the Citrix recommended alternatives.

### Running the NSPEPI tool

This tool needs to be run from the command line of the shell (you should type the `shell` command on the Citrix ADC CLI).

        nspepi [-h] (-e <classic policy expression> | -f <path to ns config file>) [-d] [-v] [-V]

Parameters:

- -h, --help: shows help message and exit  
- -e <classic policy expression>,--expression <classic policy expression>: converts classic policy expression to advanced policy expression (maximum length of 8191 allowed)  
- -f <path to ns config file>, --infile <path to ns config file>: converts Citrix ADC configuration file 
- -d, --debug: log debug output  
- -v, --verbose: shows verbose output  
- -V, --version: shows the version number of the program and exit

**Note:** Either the `-f` or `-e` parameter must be specified to perform a conversion. Use of the `-d` parameter is intended for the Citrix support team to analyze for support purposes.

The NSPEPI tool does not modify the input file. Instead, it generates two files with prefixes `new_` and `warn_` and they are put into the same directory as where the input configuration file is present. The file with the `new_ prefix` contains the converted configuration. And the file with `warn_ prefix` contains the warnings and errors. If there are any warnings or errors that got generated in the warn file, the errors must be fixed manually as part of the conversion process. Once converted, you must test the file in a test environment and then use it in the production environment to replace the actual `ns.conf` config file. After testing, you must reboot the appliance using the newly converted `ns.conf` config file.

### Best Practices:
- You must run the NSPEPI tool before upgrading to Citrix ADC release version 13.1.
- The NSPEPI tool must be run on Citrix ADC release version 12.1 or 13.0.
- For each different configuration that you need to convert:
   - Run this tool on your configuration in your existing system older than 13.1 version and do any manual changes to the output that are required.
   - Install the converted configuration on a suitable test system running on your existing Citrix ADC release version prior to 13.1 release.
   - Perform a thorough regression testing.
   - Move the configuration into production as per your normal configuration upgrade processes.
   - Run in production for a sufficient time to ensure that the configuration is working correctly on real traffic.
   - Upgrade to Citrix ADC version 13.1 using this configuration on a suitable schedule.

### Examples:
Following are a few examples of running the NSPEPI tool from the command line interface:

Example output for –e parameter:

        # nspepi -e "req.http.header foo == \"bar\""
        "HTTP.REQ.HEADER(\"foo\").EQ(\"bar\")"

Example output for -f parameter:

- Example when there are no warnings or errors:

        # cat sample.conf
        add cr vserver cr_vs HTTP -cacheType TRANSPARENT -cltTimeout 180 -originUSIP OFF
        add cr policy cr_pol1 -rule ns_true
        bind cr vserver cr_vs -policyName cr_pol1

        # nspepi -f sample.conf

        Converted config will be available in a new file new_sample.conf.
        Check warn_sample.conf file for any warnings or errors that might have been generated.

        # cat new_sample.conf

        add cr vserver cr_vs HTTP -cacheType TRANSPARENT -cltTimeout 180 -originUSIP OFF
        add cr policy cr_pol1 -rule TRUE -action ORIGIN
        bind cr vserver cr_vs -policyName cr_pol1 -priority 100 -gotoPriorityExpression END -type REQUEST

        # cat warn_sample.conf
        #

- Example when there are warnings or errors:

        # cat sample_2.conf
        add policy expression security_expr "req.tcp.destport == 80" -clientSecurityMessage "Not allowed"
        set cmp parameter -policyType CLASSIC
        add cmp policy cmp_pol1 -rule ns_true -resAction COMPRESS
        add cmp policy cmp_pol2 -rule ns_true -resAction COMPRESS
        add cmp policy cmp_pol3 -rule TRUE -resAction COMPRESS
        bind cmp global cmp_pol1bind cmp global cmp_pol2 -state DISABLED
        bind cmp global cmp_pol3 -priority 1 -gotoPriorityExpression END -type RES_DEFAULT
        bind lb vserver lb_vs -policyName cmp_pol2

        # nspepi –f sample_2.conf

        Converted config will be available in a new file new_sample_2.conf.
        Check warn_sample_2.conf file for any warnings or errors that might have been generated.

        #  cat new_sample_2.conf   
        add policy expression security_expr "req.tcp.destport == 80" -clientSecurityMessage "Not allowed"
        add cmp policy cmp_pol1 -rule TRUE -resAction COMPRESSadd cmp policy cmp_pol2 -rule TRUE -resAction COMPRESS
        add cmp policy cmp_pol3 -rule TRUE -resAction COMPRESS
        # bind cmp global cmp_pol2 -state DISABLED#bind cmp global cmp_pol3 -priority 1 -gotoPriorityExpression END -type RES_DEFAULT
        bind cmp global cmp_pol1 -priority 100 -gotoPriorityExpression END -type RES_DEFAULT
        bind lb vserver lb_vs -policyName cmp_pol2 -priority 100 -gotoPriorityExpression END -type RESPONSE
        
        #  cat warn_sample_2.conf 
        
        2021-08-15 23:38:04,337: ERROR - Error in converting expression security_expr : conversion of clientSecurityMessage based expression is not supported.

        2021-08-15 23:38:05,136: WARNING - Following bind command is commented out because state is disabled. If command is required please take a backup because comments will not be saved in ns.conf after triggering 'save ns config': bind cmp global cmp_pol2 -state DISABLED

        2021-08-15 23:38:05,138: WARNING - Bindings of advanced CMP policies to cmp global are commented out, because initial global cmp parameter isclassic but advanced policies are bound. Now global cmp parameter policytype is set to advanced. If commands are required please take a backup because comments will not be saved in ns.conf after triggering 'save ns config'.
        
        
        
- Example output of the -f parameter along with -v parameter
        
        # nspepi -f sample.conf -v 
        INFO - add cr vserver cr_vs HTTP -cacheType TRANSPARENT -cltTimeout 180 -originUSIP OFF
        INFO - add cr policy cr_pol1 -rule TRUE -action ORIGIN
        INFO - bind cr vserver cr_vs -policyName cr_pol1 -priority 100 -gotoPriorityExpression END -type REQUEST

        Converted config will be available in a new file new_sample.conf.
        Check warn_sample.conf file for any warnings or errors that might have been generated.
  
### Commands or features handled by the NSPEPI conversion tool
  
  - The following classic policies are converted to advanced policies. These policies include conversion of entity bindings including global bindings.
    - add appfw policy
    - add cmp policy
    - add cr policy
    - add cs policy
    - add tm sessionPolicy
    - add tunnel trafficPolicy
    
  - The rule parameter configured in `add lb vserver` is converted from classic expression to advanced expression.
  - Filter feature (except the FORWARD type filter action)
  - Named expressions (`add policy expression` commands). Each classic named policy expression is converted to its corresponding advanced named expression with `nspepi_adv_` set as the prefix. In addition, usage of named expressions for the converted classic expressions is changed to the corresponding advanced named expressions. Also, every named expression has two named expressions, where one is classic and the other one is advanced.
  - The SPDY parameter configured in `add ns httpProfile` or `set ns httpProfile` command is changed to `-http2 ENABLED`.
  - Patclass feature
  - Pattern parameter in rewrite action
  - SYS.EVAL_CLASSIC_EXPR is converted to the equivalent non-deprecated advanced expression. These expressions can be seen in any command where advanced expressions are allowed.
  - Q and S prefixes of advanced expressions are converted to equivalent non-deprecated advanced expressions. These expressions can be seen in any command where advanced expressions are allowed. 

For more information on the NSPEPI tool, see the [Citrix ADC documentation](https://docs.citrix.com/en-us/citrix-adc/current-release/appexpert/policies-and-expressions/introduction-to-policies-and-exp/converting-policy-expressions-nspepi-tool.html).
