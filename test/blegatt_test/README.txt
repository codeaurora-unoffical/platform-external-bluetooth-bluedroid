Bluedroid Test Application
==========================
The test application provides a small console shell interface that allows
access to the Bluetooth HAL API library though ASCII commands. This is similar
to how the real JNI service would operate. The primary objective of this
application is to allow Bluetooth to be put in DUT Mode for RF/BB BQB test purposes.

This application is mutually exclusive with the Java based Bluetooth.apk. Hence
before launching the application, it should be ensured that the Settings->Bluetooth is OFF.

This application is built as 'bdt' and shall be available in '/system/bin/bdt'

Limitations
===========
1.) Settings->Bluetooth must be OFF for this application to work
2.) Currently, only the SIG 'HCI Test Mode' commands are supported. The vendor
specific HCI test mode commands to be added.

Usage instructions
==================
The following section describes the various commands and their usage

Launching the test application
==============================
$ adb shell
root@android:/ # /system/bin/bdt
set_aid_and_cap : pid 1183, uid 0 gid 0
:::::::::::::::::::::::::::::::::::::::::::::::::::
:: Bluedroid test app starting
Loading HAL lib + extensions
HAL library loaded (Success)
INIT BT
HAL REQUEST SUCCESS

Enabling Bluetooth
==================
>enable
ENABLE BT
HAL REQUEST SUCCESS
>ADAPTER STATE UPDATED : ON

Enabling Test Mode (Bluetooth must be enabled for this command to work)
======================================================================
>dut_mode_configure 1
BT DUT MODE CONFIGURE
HAL REQUEST SUCCESS
>

Disabling Test Mode
===================
>dut_mode_configure 0
BT DUT MODE CONFIGURE
HAL REQUEST SUCCESS
>

Running BLE Test commands (Bluetooth must be enabled)
=====================================================
NOTE: Unlike BR/EDR, there is no explicit DUT mode to run these BLE tests.

> le_test_mode 1 <rx_freq>

> le_test_mode 2 <tx_freq> <test_data_len> <payload_pattern>

> le_test_mode 3 <no_args>
Please refer to the BT Core spec pages-1099 to 1102 for possible values for
the above parameters. These values need to be provided in Decimal format.

Exit the test application
=========================
>quit
shutdown bdroid test app
Unloading HAL lib
HAL library unloaded (Success)
:: Bluedroid test app terminating

Help (Lists the available commands)
===================================
>help
help lists all available console commands

quit
enable :: enables bluetooth
disable :: disables bluetooth
dut_mode_configure :: DUT mode - 1 to enter,0 to exit
le_test_mode :: LE Test Mode - RxTest - 1 <rx_freq>,
                               TxTest - 2 <tx_freq> <test_data_len> <payload_pattern>,
                               End Test - 3 <no_args>


proceduredure to create LE-L2CAP Connection Oriented Channal
============================================================
Step 1:
        --> Run the gatt_testtool executable on both side (i.e, peripheral & central)

Step 2:
        Start Advertisement
        ===================

        > start_adv <uuid> <flag> ( peripheral side )

        Where,
                flag     -->    1 (start advertisement)
                                 0 (stop advertisement)

                option    -->    1 (Doing registration with only Gatt_cb which is required for LE-L2CAP)
                                 0 (Doing the existing s_registration for gatt_testtool)

        This will start the advertisement and listen for the incoming LE connection.

Step 3:
        Start&Stop scanning
        ===================

        > c_scan_start  ( central side )
        > c_scan_stop ( stop it as and when we find the remote device) ( Central side)

Step 4:
       listen for incoming LE COC
       ==========================

        > le_l2cap_listen  <le_psm> <mtu> <mps> <init_credits> <sec_level> ( peripheral side )

        Where,
                le_psm          -->     1 to 127 (Fixed Range, SIG assigned)
                                        128 to 255 (Dynamic Range)
                mtu             -->     23 to 65535
                mps             -->     23 to 65533
                init_credits    -->     0 to 65535
                sec_level       -->     0 for no security
                                        1 for authentication
                                -->     2 for encryption

        Example : le_l2cap_listen 128 23 23 100 0
        Note : MTU value should not be less then MPS

Step 5:
        Initiate LE COC connection
        ==========================

        > le_l2cap_coc_connect  <le_psm> <mtu> <mps> <init_credits> <sec_level> <bd_addr> ( central side)

        Where,
                le_psm          -->     1 to 127 (Fixed Range, SIG assigned)
                                        128 to 255 (Dynamic Range)
                mtu             -->     23 to 65535
                mps             -->     23 to 65533
                init_credits    -->     0 to 65535
                bd_addr         -->     remote BD address
                sec_level       -->     0 for no security
                                        1 for authentication
                                -->     2 for encryption

        Example :  le_l2cap_coc_connect 128 23 23 100 0 7e58587530b8
        Note : MTU value should not be less then MPS

Step 6:
        Send Credits [LE Credit Based Flow Control Mode]
        ================================================

        [Initiating the LE credit based flow control with the no.of credits incase of initial credits were
         not provided i.e set as 0 as part of connection establishment, this command will be ignored
         if the intial credits were given as part of conneciton establishment.]

        > le_l2cap_coc_flow_ctrl <cid> <credits>

        Where,
                cid             -->     64 to 127 (Dynamic Range)
                                        [ Use the allocated CID during LE COC connection initialization]
                credits         -->     1 to 65535

        Note : When we plan to send this command, the initial credit value has to be set with zero
               during the initialization LE COC connection.

Step 7:
        Send file
        =========

        push the file in to the device "/system" directory which you want to sent.

        > send_file <cid> < file_path >

        Where,
                cid             -->     64 to 127 (Dynamic Range)
                                        [ Use the allocated CID during LE COC connection initialization]
                file_path       -->     give the file path which is going to be sent.

        Example : send_file 65 /system/bt_stack_file.txt

Step 8:
        Disconnect LE COC
        =================

        > le_coc_disconnect <cid>

        Where,
                cid             -->     64 to 127 (Dynamic Range)
                                        [ Use the allocated CID during LE COC connection initialization]

