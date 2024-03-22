// Generic TTPs

rule mal_kubo_plthook : TESTING TOOL PLTHOOK TA0005 T1574 {
    meta:
        version     = "1.0"
        score       = 80
        date        = "2024-02-05"
        modified    = "2024-02-15"
        status      = "TESTING"
        source      = "NVISO"
        author      = "Maxime THIEBAUT"
        description = "Detects traces of PLTHook hooking"
        category    = "TOOL"
        tool        = "KUBO/PLTHOOK"
        mitre_att   = "T1574"
        reference   = "https://github.com/kubo/plthook"
        license     = "Detection Rule License (DRL) 1.1"

    strings:
        $close      = "plthook_close"
        $enum       = "plthook_enum"
        $error      = "plthook_error"
        $open       = "plthook_open"
        $address    = "plthook_open_by_address"
        $handle     = "plthook_open_by_handle"
        $replace    = "plthook_replace"
        
    condition:
        any of them
}

rule mal_kubo_injector : TESTING TOOL INJECTOR TA0005 T1055 T1055_001 {
    meta:
        version     = "1.0"
        score       = 80
        date        = "2024-02-13"
        modified    = "2024-02-15"
        status      = "TESTING"
        source      = "NVISO"
        author      = "Maxime THIEBAUT"
        description = "Detects traces of injection capabilities"
        category    = "TOOL"
        tool        = "KUBO/INJECTOR"
        mitre_att   = "T1055_001"
        reference   = "https://github.com/kubo/injector"
        license     = "Detection Rule License (DRL) 1.1"

    strings:
        $ext_attach     = "injector_attach"
        $ext_detach     = "injector_detach"
        $ext_inject     = "injector_inject"
        
        $int_errmsg     = "injector__set_errmsg"
        $int_call_func  = "injector__call_function"
        $int_write      = "injector__write"
        $int_isset      = "injector__errmsg_is_set"
        $int_call_sys   = "injector__call_syscall"
        $int_detach     = "injector__detach_process"
        $int_ptrace     = "injector__ptrace"
        $int_regs_set   = "injector__set_regs"
        $int_continue   = "injector__continue"
        $int_regs_get   = "injector__get_regs"
        $int_arch       = "injector__arch2name"
        
        $err_stopped    = "The target process unexpectedly stopped by signal %d."
        $err_terminated = "The target process unexpectedly terminated by signal %d."
        $err_exited     = "The target process unexpectedly terminated with exit code %d."
        $err_wait       = "waitpid error while attaching: %s"
        $err_abi        = "x32-ABI target process is supported only by x86_64."
        
    condition:
        2 of ($ext_*)
        or any of ($int_*)
        or 3 of ($err_*)
}

rule sus_x509_self_signed : TESTING TOOL OPENSSL TA0011 T1573 T1573_002 {
    meta:
        version     = "1.0"
        score       = 50
        date        = "2024-02-05"
        modified    = "2024-02-15"
        status      = "TESTING"
        source      = "NVISO"
        author      = "Maxime THIEBAUT"
        description = "Detects a potential PEM-encoded default OpenSSL organization with associated RSA private key"
        category    = "TOOL"
        tool        = "OPENSSL"
        mitre_att   = "T1573.002"
        license     = "Detection Rule License (DRL) 1.1"

    strings:
        $widgits    =  "Internet Widgits Pty Ltd" base64 base64wide
        $pem        = /-----BEGIN RSA PRIVATE KEY-----\n[-A-Za-z0-9+\/=]{64}\n/
        
    condition:
        all of them
}

rule sus_pulsesecure_integrity_bypass : TESTING BYPASS TA0005 T1562 T1562_001 {
    meta:
        version     = "1.0"
        score       = 50
        date        = "2024-02-15"
        modified    = "2024-02-15"
        status      = "TESTING"
        source      = "NVISO"
        author      = "Maxime THIEBAUT"
        description = "Detects a potential Pulse Secure integrety bypass"
        mitre_att   = "T1562.001"
        license     = "Detection Rule License (DRL) 1.1"

    strings:
        $bypass = ">> /home/etc/manifest/exclusion_list"
        
    condition:
        all of them and filesize < 10KB
}


rule sus_sparkgateway_plugin_jar : TESTING TOOL REMOTESPARK TA0003 T1554 {
    meta:
        version     = "1.0"
        score       = 50
        date        = "2024-02-05"
        modified    = "2024-02-15"
        status      = "TESTING"
        source      = "NVISO"
        author      = "Maxime THIEBAUT"
        description = "Detects a potential Spark Gateway plugin, abused by the SparkCockpit and SparkTar backdoors for persistence"
        category    = "TOOL"
        tool        = "REMOTE SPARK"
        mitre_att   = "T1554"
        license     = "Detection Rule License (DRL) 1.1"

    strings:
        $manifest       = "META-INF/MANIFEST.MF"    fullword
        $class_spark_2  = "SparkPlugin$1.class"     fullword
        $class_spark_1  = "SparkPlugin.class"       fullword
        $class_toremote = "com/toremote/gateway/plugin/PluginManager" fullword
        
    condition:
        uint32(0) == 0x04034B50
        and $manifest
        and any of ($class_*)
        and filesize < 10KB
}

// BUSHWALK rules

rule mal_webshell_bushwalk_stager : TESTING MALWARE BUSHWALK TA0003 T1505 T1505_003 {
    meta:
        version     = "1.0"
        score       = 90
        date        = "2024-02-16"
        modified    = "2024-02-16"
        status      = "TESTING"
        source      = "NVISO"
        author      = "Maxime THIEBAUT"
        description = "Detects string patterns related to the BUSHWALK webshell's user-agent stager"
        category    = "MALWARE"
        tool        = "BUSHWALK"
        mitre_att   = "T1505.003"
        reference   = "https://www.mandiant.com/resources/blog/investigating-ivanti-zero-day-exploitation"
        license     = "Detection Rule License (DRL) 1.1"

    strings:
        $ua_typo_1  = "App1eWebKit" fullword
        $ua_typo_I  = "AppIeWebKit" fullword
        
        $shell_decrypt  = "configdecrypt" fullword
        $shell_exec     = "system("       fullword
        $shell_target   = ".cgi"
        
        $op_mount_rw    = "mount -o remount,rw"      fullword
        $op_mount_ro    = "mount -o remount,ro"      fullword
        $op_restart     = "restartServer.pl Restart" fullword
        
        
    condition:
        filesize < 10KB and (
            all of ($ua_typo_*)
            or all of ($shell_*)
            or all of ($op_*)
        )
}

rule mal_webshell_bushwalk : TESTING MALWARE BUSHWALK TA0003 T1505 T1505_003 {
    meta:
        version     = "1.0"
        score       = 90
        date        = "2024-02-05"
        modified    = "2024-02-15"
        status      = "TESTING"
        source      = "NVISO"
        author      = "Maxime THIEBAUT"
        description = "Detects string patterns related to the BUSHWALK webshell"
        category    = "MALWARE"
        tool        = "BUSHWALK"
        mitre_att   = "T1505.003"
        reference   = "https://www.mandiant.com/resources/blog/investigating-ivanti-zero-day-exploitation"
        license     = "Detection Rule License (DRL) 1.1"

    strings:
        $parse_platform = "SafariiOS"       fullword
        $parse_rc4      = "RC4($key, $data)"
        $parse_params   = "@param1 = split(\"@\",$data)"
        $parse_action   = "@action = split(\"=\",$param1[0])"
        
        $exec_command   = "change"          fullword
        $exec_func      = "changeVersion"   fullword
        $exec_rc4       = "RC4($key, $ts)"
        
        $read_command   = "check"           fullword
        $read_func      = "checkVerison"    fullword
        $read_rc4       = "RC4($key, $contents)"
        
        $write_command  = "update"          fullword
        $write_func     = "updateVersion"   fullword
        
    condition:
        filesize < 10KB and (
            2 of ($parse_*) or
            any of ($parse_*) and (
                2 of ($exec_*)
                or 2 of ($read_*)
                or all of ($write_*)
            )
        )
}


// SparkCockpit rules

rule mal_backdoor_sparkcockpit_sniffer : TESTING MALWARE SPARKCOCKPIT TA0011 T1205 T1205_002 {
    meta:
        version     = "1.0"
        score       = 90
        date        = "2024-02-05"
        modified    = "2024-02-15"
        status      = "TESTING"
        source      = "NVISO"
        author      = "Maxime THIEBAUT"
        description = "Detects suspicious patterns related to TLS Client Hello traffic signalling received by the SparkCockpit backdoor"
        category    = "MALWARE"
        tool        = "SPARKCOCKPIT"
        mitre_att   = "T1205.002"
        license     = "Detection Rule License (DRL) 1.1"

    strings:
        $logic_target   = "accept"          fullword
        $logic_target4  = "accept4"         fullword
        $logic_orig     = "origin_accept"   fullword
        $logic_orig4    = "origin_accept4"  fullword
        $logic_ciphers  = {
            00 6B // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
            CC AA // TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            C0 24 // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
            C0 14 // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        }
        
    condition:
        4 of them and filesize <= 1MB
}


rule mal_backdoor_sparkcockpit_controller : TESTING MALWARE SPARKCOCKPIT TA0001 T1573 {
    meta:
        version     = "1.0"
        score       = 100
        date        = "2024-02-05"
        modified    = "2024-02-15"
        status      = "TESTING"
        source      = "NVISO"
        author      = "Maxime THIEBAUT"
        description = "Detects patterns related to the SparkCockpit backdoor controller"
        category    = "MALWARE"
        tool        = "SPARKCOCKPIT"
        mitre_att   = "T1573"
        license     = "Detection Rule License (DRL) 1.1"

    strings:
        $aes_key = {1F 8D 37 98 4C 88 1D 07 DA AA 6B 7C 43 9A 27 1B}
        
        $cmd_exec       = "exec:"   fullword
        $cmd_upload     = "upx:"    fullword
        $cmd_download   = "dld:"    fullword
        
        $status_written = " written!"       fullword
        $status_read    = " reading done!"  fullword
        
        $err_chdir      = "change dir failed"           fullword
        $err_stat       = "get file decription failed"  fullword
        
        $exec_busybox       = "//bin/bash"  fullword
        $exec_busybox_flag  = "-c"          fullword
        $exec_node          = "/bin/node"   fullword
        $exec_node_flag     = "-e"          fullword
        
    condition:
        ($aes_key 
        or 2 of ($cmd_*)
        or all of ($status*)
        or any of ($err_*)
        or all of ($exec_*))
        and filesize <= 5MB
}

rule mal_backdoor_sparkcockpit_plugin_mem : TESTING MALWARE SPARKCOCKPIT TA0003 T1554 {
    meta:
        version     = "1.0"
        score       = 80
        date        = "2024-02-05"
        modified    = "2024-02-15"
        status      = "TESTING"
        source      = "NVISO"
        author      = "Maxime THIEBAUT"
        description = "Detects in-memory traces of the SparkCockpit backdoor's Spark Gateway persistance plugin"
        category    = "MALWARE"
        tool        = "SPARKCOCKPIT"
        mitre_att   = "T1554"
        license     = "Detection Rule License (DRL) 1.1"

    strings:
        $candidate_identification   = "ps aux|grep '/home/bin/web'|grep -v grep | awk '{if (NR!=1) {print $2}}'"
        $candidate_validation       = "cat /proc/%d/maps | grep mem.rd"
        $candidate_injection        = "memorysCounter -p %d "
        $control_identification     = "|grep -v grep | awk '{print $2}'"
        
    condition:
        2 of them
}

// SparkTar rules

rule mal_backdoor_sparktar_sniffer : TESTING MALWARE SPARKTAR TA0011 T1205 T1205_002 {
    meta:
        version     = "1.0"
        score       = 80
        date        = "2024-02-05"
        modified    = "2024-02-15"
        status      = "TESTING"
        source      = "NVISO"
        author      = "Maxime THIEBAUT"
        description = "Detects suspicious patterns related to TLS Client Hello traffic signalling received by the SparkTar backdoor"
        category    = "MALWARE"
        tool        = "SPARKTAR"
        mitre_att   = "T1205.002"
        license     = "Detection Rule License (DRL) 1.1"

    strings:
        $accept     = "accept"                    fullword
        $setsockopt = "setsockopt"                fullword
        $socket     = "/tmp/clientsDownload.sock" fullword
        $random     = { DA F3 64 13 B2 74 C3 A1}
        
    condition:
        3 of them and filesize <= 3MB
}

rule mal_backdoor_sparktar_tar : TESTING MALWARE SPARKTAR TA0005 T1036 T1036_005 {
    meta:
        version     = "1.0"
        score       = 90
        date        = "2024-02-05"
        modified    = "2024-02-15"
        status      = "TESTING"
        source      = "NVISO"
        author      = "Maxime THIEBAUT"
        description = "Detects suspicious patterns related to the SparkTar backdoor's TAR archive wrapper"
        category    = "MALWARE"
        tool        = "SPARKTAR"
        mitre_att   = "T1036.005"
        license     = "Detection Rule License (DRL) 1.1"

    strings:
        $nodata  = "no-data"                 fullword
        $upgrade = "/bin/samba_upgrade.tar"  fullword
        $tar     = "/bin/tra"                fullword
        
    condition:
        all of them
}

rule mal_backdoor_sparktar_controller : TESTING MALWARE SPARKTAR TA0001 T1573 {
    meta:
        version     = "1.0"
        score       = 100
        date        = "2024-02-05"
        modified    = "2024-02-15"
        status      = "TESTING"
        source      = "NVISO"
        author      = "Maxime THIEBAUT"
        description = "Detects patterns related to the SparkTar backdoor controller"
        category    = "MALWARE"
        tool        = "SPARKTAR"
        mitre_att   = "T1573"
        license     = "Detection Rule License (DRL) 1.1"

    strings:
        $pulse_target   = "/home/bin/web"                           fullword
        $pulse_cert     = "/home/webserver/conf/ssl.crt/secure.crt" fullword
        $pulse_key      = "/home/webserver/conf/ssl.key/secure.key" fullword
        $pulse_socket   = "/tmp/clientsDownload.sock"               fullword
        $pulse_cmdline  = "/proc/%s/cmdline"                        fullword
        
        $file_sniffer       = "SparkGateway/libaprhelper.so"    fullword
        $file_controller    = "SparkGateway/libchilkat.so"      fullword
        $file_mutex         = "SparkGateway/no-data"            fullword
        
        $factory_serial = "/proc/ive/mbserialnumber"        fullword
        $factory_md5    = "losetup /dev/loop5 /dev/md5"     fullword
        $factory_xda5   = "losetup /dev/loop5 /dev/xda5"    fullword
        $factory_mnt    = "/tmp/tmpmnt"                     fullword
        
        $persist_stat       = "/SparkGateway/gateway.conf"
        $persist_manager    = "PluginManager"   fullword
        $persist_comment    = "plugin = com."
        $persist_patch      = "pluginFile ="
               
        $obj_node       = "AgentNode"
        $obj_child      = "AgentNodeChild"
        $obj_socks      = "SocksServer"
        $obj_tunnel     = "Tunnel"
        $obj_topology   = "Topology"
        
        $func_clean_admin   = "remove_admin_node"
        $func_clean_tunnel  = "cleanup_all_tunnel"
        $func_clean_shell   = "cleanup_exshell"
        $func_clean_file    = "clear_local_file_status"
        
        $func_send_all      = "send_all_agentnode_children_message_to_admin_node"
        $func_send_admin    = "send_data_to_admin_node"
        
        $func_wait_cmd  = "waitfor_cmd_thread_end"
        $func_wait_file = "waitfor_filedownload_thread_stop"
        
        $func_listen        = "listen_for_agentchild"
        $func_handle_shell  = "handle_exshell_"
        $func_handle_tunnel = "handle_tunnel_"
        $func_handle_socks  = "handle_socks_"
        
    condition:
        4 of ($pulse_*)
        or any of ($file_*)
        or 3 of ($factory_*)
        or 3 of ($persist_*)
        or 4 of ($obj_*)
        or 3 of ($func_*)
}