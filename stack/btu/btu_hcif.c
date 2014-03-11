/******************************************************************************
 *
 *  Copyright (C) 1999-2012 Broadcom Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

/******************************************************************************
 *
 *  This file contains functions that interface with the HCI transport. On
 *  the receive side, it routes events to the appropriate handler, e.g.
 *  L2CAP, ScoMgr. On the transmit side, it manages the command
 *  transmission.
 *
 ******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "gki.h"
#include "bt_types.h"
#include "hcimsgs.h"
#include "btu.h"
#include "l2c_int.h"
#include "btm_api.h"
#include "btm_int.h"
#include "bt_target.h"
// btla-specific ++
#define LOG_TAG "BTLD"
#if (defined(ANDROID_APP_INCLUDED) && (ANDROID_APP_INCLUDED == TRUE) && (!defined(LINUX_NATIVE)) )
#include <cutils/log.h>
#else
#define LOGV(format, ...)  fprintf (stdout, LOG_TAG format"\n", ## __VA_ARGS__)
#define LOGE(format, ...)  fprintf (stderr, LOG_TAG format"\n", ## __VA_ARGS__)
#define LOGI(format, ...)  fprintf (stdout, LOG_TAG format"\n", ## __VA_ARGS__)
#endif

// btla-specific ++
/* BTE application task */
#if APPL_INCLUDED == TRUE
#include "bte_appl.h"
#endif
// btla-specific --

//Counter to track number of HCI command timeout
static int num_hci_cmds_timed_out;

/********************************************************************************/
/*              L O C A L    F U N C T I O N     P R O T O T Y P E S            */
/********************************************************************************/
static void btu_hcif_inquiry_comp_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_inquiry_result_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_inquiry_rssi_result_evt (UINT8 *p, UINT16 evt_len);
#if (BTM_EIR_CLIENT_INCLUDED == TRUE)
static void btu_hcif_extended_inquiry_result_evt (UINT8 *p, UINT16 evt_len);
#endif

static void btu_hcif_connection_comp_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_connection_request_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_disconnection_comp_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_authentication_comp_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_rmt_name_request_comp_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_encryption_change_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_change_conn_link_key_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_master_link_key_comp_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_read_rmt_features_comp_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_read_rmt_ext_features_comp_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_read_rmt_version_comp_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_qos_setup_comp_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_command_complete_evt (UINT8 controller_id, UINT8 *p, UINT16 evt_len);
static void btu_hcif_command_status_evt (UINT8 controller_id, UINT8 *p, UINT16 evt_len);
static void btu_hcif_hardware_error_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_flush_occured_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_role_change_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_num_compl_data_pkts_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_mode_change_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_return_link_keys_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_pin_code_request_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_link_key_request_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_link_key_notification_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_loopback_command_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_data_buf_overflow_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_max_slots_changed_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_read_clock_off_comp_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_conn_pkt_type_change_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_qos_violation_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_page_scan_mode_change_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_page_scan_rep_mode_chng_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_esco_connection_comp_evt(UINT8 *p, UINT16 evt_len);
static void btu_hcif_esco_connection_chg_evt(UINT8 *p, UINT16 evt_len);

/* Simple Pairing Events */
static void btu_hcif_host_support_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_io_cap_request_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_io_cap_response_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_user_conf_request_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_user_passkey_request_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_user_passkey_notif_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_keypress_notif_evt (UINT8 *p, UINT16 evt_len);
static void btu_hcif_link_super_tout_evt (UINT8 *p, UINT16 evt_len);

    #if BTM_OOB_INCLUDED == TRUE
static void btu_hcif_rem_oob_request_evt (UINT8 *p, UINT16 evt_len);
    #endif

static void btu_hcif_simple_pair_complete_evt (UINT8 *p, UINT16 evt_len);
    #if L2CAP_NON_FLUSHABLE_PB_INCLUDED == TRUE
static void btu_hcif_enhanced_flush_complete_evt (UINT8 *p, UINT16 evt_len);
    #endif

    #if (BTM_SSR_INCLUDED == TRUE)
static void btu_hcif_ssr_evt (UINT8 *p, UINT16 evt_len);
    #endif /* BTM_SSR_INCLUDED == TRUE */

    #if (HID_DEV_INCLUDED == TRUE) && (HID_DEV_PM_INCLUDED == TRUE)
extern void hidd_pm_proc_mode_change( UINT8 hci_status, UINT8 mode, UINT16 interval );
    #endif


    #if BLE_INCLUDED == TRUE
static void btu_ble_ll_conn_complete_evt (UINT8 *p, UINT16 evt_len);
static void btu_ble_process_adv_pkt (UINT8 *p, UINT16 evt_len);
static void btu_ble_read_remote_feat_evt (UINT8 *p, UINT16 evt_len);
static void btu_ble_ll_conn_param_upd_evt (UINT8 *p, UINT16 evt_len);
static void btu_ble_proc_ltk_req (UINT8 *p, UINT16 evt_len);
static void btu_hcif_encyption_key_refresh_cmpl_evt (UINT8 *p, UINT16 evt_len);
static void btu_ble_ll_conn_param_req_evt (UINT8 *p, UINT16 evt_len);
    #endif
/*******************************************************************************
**
** Function         btu_hcif_store_cmd
**
** Description      This function stores a copy of an outgoing command and
**                  and sets a timer waiting for a event in response to the
**                  command.
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_store_cmd (UINT8 controller_id, BT_HDR *p_buf)
{
    tHCI_CMD_CB *p_hci_cmd_cb;
    UINT16  opcode;
    BT_HDR  *p_cmd;
    UINT8   *p;

    /* Validate controller ID */
    if (controller_id >= BTU_MAX_LOCAL_CTRLS)
        return;

    p_hci_cmd_cb = &(btu_cb.hci_cmd_cb[controller_id]);
    p = (UINT8 *)(p_buf + 1) + p_buf->offset;

    /* get command opcode */
    STREAM_TO_UINT16 (opcode, p);

    /* don't do anything for certain commands */
    if ((opcode == HCI_RESET) || (opcode == HCI_HOST_NUM_PACKETS_DONE))
    {
        return;
    }

    /* allocate buffer (HCI_GET_CMD_BUF will either get a buffer from HCI_CMD_POOL or from 'best-fit' pool) */
    if ((p_cmd = HCI_GET_CMD_BUF(p_buf->len + p_buf->offset - HCIC_PREAMBLE_SIZE)) == NULL)
    {
        return;
    }

    /* copy buffer */
    memcpy (p_cmd, p_buf, sizeof(BT_HDR));

    /* If vendor specific save the callback function */
    if ((opcode & HCI_GRP_VENDOR_SPECIFIC) == HCI_GRP_VENDOR_SPECIFIC
#if BLE_INCLUDED == TRUE
        || (opcode == HCI_BLE_RAND )
        || (opcode == HCI_BLE_ENCRYPT)
#endif
       )
    {
#if 0
        BT_TRACE_2 (TRACE_LAYER_HCI, TRACE_TYPE_DEBUG,
                    "Storing VSC callback opcode=0x%04x, Callback function=0x%07x",
                    opcode, *(UINT32 *)(p_buf + 1));
#endif
        memcpy ((UINT8 *)(p_cmd + 1), (UINT8 *)(p_buf + 1), sizeof(void *));
    }

    memcpy ((UINT8 *)(p_cmd + 1) + p_cmd->offset,
            (UINT8 *)(p_buf + 1) + p_buf->offset, p_buf->len);

    /* queue copy of cmd */
    GKI_enqueue(&(p_hci_cmd_cb->cmd_cmpl_q), p_cmd);

    /* start timer */
    if (BTU_CMD_CMPL_TIMEOUT > 0)
    {
#if (defined(BTU_CMD_CMPL_TOUT_DOUBLE_CHECK) && BTU_CMD_CMPL_TOUT_DOUBLE_CHECK == TRUE)
        p_hci_cmd_cb->checked_hcisu = FALSE;
#endif
        btu_start_timer (&(p_hci_cmd_cb->cmd_cmpl_timer),
                         (UINT16)(BTU_TTYPE_BTU_CMD_CMPL + controller_id),
                         BTU_CMD_CMPL_TIMEOUT);
    }
}

/*******************************************************************************
**
** Function         btu_hcif_process_event
**
** Description      This function is called when an event is received from
**                  the Host Controller.
**
** Returns          void
**
*******************************************************************************/
void btu_hcif_process_event (UINT8 controller_id, BT_HDR *p_msg)
{
    UINT8   *p = (UINT8 *)(p_msg + 1) + p_msg->offset;
    UINT8   hci_evt_code, hci_evt_len;
#if BLE_INCLUDED == TRUE
    UINT8   ble_sub_code;
#endif
    STREAM_TO_UINT8  (hci_evt_code, p);
    STREAM_TO_UINT8  (hci_evt_len, p);

    switch (hci_evt_code)
    {
        case HCI_INQUIRY_COMP_EVT:
            btu_hcif_inquiry_comp_evt (p, hci_evt_len);
            break;
        case HCI_INQUIRY_RESULT_EVT:
            btu_hcif_inquiry_result_evt (p, hci_evt_len);
            break;
        case HCI_INQUIRY_RSSI_RESULT_EVT:
            btu_hcif_inquiry_rssi_result_evt (p, hci_evt_len);
            break;
#if (BTM_EIR_CLIENT_INCLUDED == TRUE)
        case HCI_EXTENDED_INQUIRY_RESULT_EVT:
            btu_hcif_extended_inquiry_result_evt (p, hci_evt_len);
            break;
#endif
        case HCI_CONNECTION_COMP_EVT:
            btu_hcif_connection_comp_evt (p, hci_evt_len);
            break;
        case HCI_CONNECTION_REQUEST_EVT:
            btu_hcif_connection_request_evt (p, hci_evt_len);
            break;
        case HCI_DISCONNECTION_COMP_EVT:
            btu_hcif_disconnection_comp_evt (p, hci_evt_len);
            break;
        case HCI_AUTHENTICATION_COMP_EVT:
            btu_hcif_authentication_comp_evt (p, hci_evt_len);
            break;
        case HCI_RMT_NAME_REQUEST_COMP_EVT:
            btu_hcif_rmt_name_request_comp_evt (p, hci_evt_len);
            break;
        case HCI_ENCRYPTION_CHANGE_EVT:
            btu_hcif_encryption_change_evt (p, hci_evt_len);
            break;
#if BLE_INCLUDED == TRUE
        case HCI_ENCRYPTION_KEY_REFRESH_COMP_EVT:
            btu_hcif_encyption_key_refresh_cmpl_evt(p, hci_evt_len);
            break;
#endif
        case HCI_CHANGE_CONN_LINK_KEY_EVT:
            btu_hcif_change_conn_link_key_evt (p, hci_evt_len);
            break;
        case HCI_MASTER_LINK_KEY_COMP_EVT:
            btu_hcif_master_link_key_comp_evt (p, hci_evt_len);
            break;
        case HCI_READ_RMT_FEATURES_COMP_EVT:
            btu_hcif_read_rmt_features_comp_evt (p, hci_evt_len);
            break;
        case HCI_READ_RMT_EXT_FEATURES_COMP_EVT:
            btu_hcif_read_rmt_ext_features_comp_evt (p, hci_evt_len);
            break;
        case HCI_READ_RMT_VERSION_COMP_EVT:
            btu_hcif_read_rmt_version_comp_evt (p, hci_evt_len);
            break;
        case HCI_QOS_SETUP_COMP_EVT:
            btu_hcif_qos_setup_comp_evt (p, hci_evt_len);
            break;
        case HCI_COMMAND_COMPLETE_EVT:
            btu_hcif_command_complete_evt (controller_id, p, hci_evt_len);
            break;
        case HCI_COMMAND_STATUS_EVT:
            btu_hcif_command_status_evt (controller_id, p, hci_evt_len);
            break;
        case HCI_HARDWARE_ERROR_EVT:
            btu_hcif_hardware_error_evt (p, hci_evt_len);
            break;
        case HCI_FLUSH_OCCURED_EVT:
            btu_hcif_flush_occured_evt (p, hci_evt_len);
            break;
        case HCI_ROLE_CHANGE_EVT:
            btu_hcif_role_change_evt (p, hci_evt_len);
            break;
        case HCI_NUM_COMPL_DATA_PKTS_EVT:
            btu_hcif_num_compl_data_pkts_evt (p, hci_evt_len);
            break;
        case HCI_MODE_CHANGE_EVT:
            btu_hcif_mode_change_evt (p, hci_evt_len);
            break;
        case HCI_RETURN_LINK_KEYS_EVT:
            btu_hcif_return_link_keys_evt (p, hci_evt_len);
            break;
        case HCI_PIN_CODE_REQUEST_EVT:
            btu_hcif_pin_code_request_evt (p, hci_evt_len);
            break;
        case HCI_LINK_KEY_REQUEST_EVT:
            btu_hcif_link_key_request_evt (p, hci_evt_len);
            break;
        case HCI_LINK_KEY_NOTIFICATION_EVT:
            btu_hcif_link_key_notification_evt (p, hci_evt_len);
            break;
        case HCI_LOOPBACK_COMMAND_EVT:
            btu_hcif_loopback_command_evt (p, hci_evt_len);
            break;
        case HCI_DATA_BUF_OVERFLOW_EVT:
            btu_hcif_data_buf_overflow_evt (p, hci_evt_len);
            break;
        case HCI_MAX_SLOTS_CHANGED_EVT:
            btu_hcif_max_slots_changed_evt (p, hci_evt_len);
            break;
        case HCI_READ_CLOCK_OFF_COMP_EVT:
            btu_hcif_read_clock_off_comp_evt (p, hci_evt_len);
            break;
        case HCI_CONN_PKT_TYPE_CHANGE_EVT:
            btu_hcif_conn_pkt_type_change_evt (p, hci_evt_len);
            break;
        case HCI_QOS_VIOLATION_EVT:
            btu_hcif_qos_violation_evt (p, hci_evt_len);
            break;
        case HCI_PAGE_SCAN_MODE_CHANGE_EVT:
            btu_hcif_page_scan_mode_change_evt (p, hci_evt_len);
            break;
        case HCI_PAGE_SCAN_REP_MODE_CHNG_EVT:
            btu_hcif_page_scan_rep_mode_chng_evt (p, hci_evt_len);
            break;
        case HCI_ESCO_CONNECTION_COMP_EVT:
            btu_hcif_esco_connection_comp_evt (p, hci_evt_len);
            break;
        case HCI_ESCO_CONNECTION_CHANGED_EVT:
            btu_hcif_esco_connection_chg_evt (p, hci_evt_len);
            break;
#if (BTM_SSR_INCLUDED == TRUE)
        case HCI_SNIFF_SUB_RATE_EVT:
            btu_hcif_ssr_evt (p, hci_evt_len);
            break;
#endif  /* BTM_SSR_INCLUDED == TRUE */
        case HCI_RMT_HOST_SUP_FEAT_NOTIFY_EVT:
            btu_hcif_host_support_evt (p, hci_evt_len);
            break;
        case HCI_IO_CAPABILITY_REQUEST_EVT:
            btu_hcif_io_cap_request_evt (p, hci_evt_len);
            break;
        case HCI_IO_CAPABILITY_RESPONSE_EVT:
            btu_hcif_io_cap_response_evt (p, hci_evt_len);
            break;
        case HCI_USER_CONFIRMATION_REQUEST_EVT:
            btu_hcif_user_conf_request_evt (p, hci_evt_len);
            break;
        case HCI_USER_PASSKEY_REQUEST_EVT:
            btu_hcif_user_passkey_request_evt (p, hci_evt_len);
            break;
#if BTM_OOB_INCLUDED == TRUE
        case HCI_REMOTE_OOB_DATA_REQUEST_EVT:
            btu_hcif_rem_oob_request_evt (p, hci_evt_len);
            break;
#endif
        case HCI_SIMPLE_PAIRING_COMPLETE_EVT:
            btu_hcif_simple_pair_complete_evt (p, hci_evt_len);
            break;
        case HCI_USER_PASSKEY_NOTIFY_EVT:
            btu_hcif_user_passkey_notif_evt (p, hci_evt_len);
            break;
        case HCI_KEYPRESS_NOTIFY_EVT:
            btu_hcif_keypress_notif_evt (p, hci_evt_len);
            break;
        case HCI_LINK_SUPER_TOUT_CHANGED_EVT:
            btu_hcif_link_super_tout_evt (p, hci_evt_len);
            break;
#if L2CAP_NON_FLUSHABLE_PB_INCLUDED == TRUE
        case HCI_ENHANCED_FLUSH_COMPLETE_EVT:
            btu_hcif_enhanced_flush_complete_evt (p, hci_evt_len);
            break;
#endif

#if (BLE_INCLUDED == TRUE)
        case HCI_BLE_EVENT:
            STREAM_TO_UINT8  (ble_sub_code, p);

            BT_TRACE_2 (TRACE_LAYER_HCI, TRACE_TYPE_EVENT, "BLE HCI(id=%d) event = 0x%02x)",
                        hci_evt_code,  ble_sub_code);

            switch (ble_sub_code)
            {
                case HCI_BLE_ADV_PKT_RPT_EVT: /* result of inquiry */
                    btu_ble_process_adv_pkt(p, hci_evt_len);
                    break;
                case HCI_BLE_CONN_COMPLETE_EVT:
                    btu_ble_ll_conn_complete_evt(p, hci_evt_len);
                    break;
                case HCI_BLE_LL_CONN_PARAM_UPD_EVT:
                    btu_ble_ll_conn_param_upd_evt(p, hci_evt_len);
                    break;
                case HCI_BLE_READ_REMOTE_FEAT_CMPL_EVT:
                    btu_ble_read_remote_feat_evt(p, hci_evt_len);
                    break;
                case HCI_BLE_LTK_REQ_EVT: /* received only at slave device */
                    btu_ble_proc_ltk_req(p, hci_evt_len);
                    break;
                case HCI_BLE_LL_CONN_PARAM_REQ_EVT:
                    btu_ble_ll_conn_param_req_evt(p, hci_evt_len);
                    break;
            }
            break;
#endif /* BLE_INCLUDED */
        case HCI_VENDOR_SPECIFIC_EVT:
                btm_vendor_specific_evt (p, hci_evt_len);
            break;
    }
#if HCI_RAW_CMD_INCLUDED == TRUE
    btm_hci_event (p, hci_evt_code , hci_evt_len);
#endif

    // reset the  num_hci_cmds_timed_out upon receving any event from controller.
    num_hci_cmds_timed_out = 0;
}


/*******************************************************************************
**
** Function         btu_hcif_send_cmd
**
** Description      This function is called to check if it can send commands
**                  to the Host Controller. It may be passed the address of
**                  a packet to send.
**
** Returns          void
**
*******************************************************************************/
void btu_hcif_send_cmd (UINT8 controller_id, BT_HDR *p_buf)
{
    tHCI_CMD_CB * p_hci_cmd_cb = &(btu_cb.hci_cmd_cb[controller_id]);

#if ((L2CAP_HOST_FLOW_CTRL == TRUE)||defined(HCI_TESTER))
    UINT8 *pp;
    UINT16 code;
#endif

    /* If there are already commands in the queue, then enqueue this command */
    if ((p_buf) && (p_hci_cmd_cb->cmd_xmit_q.count))
    {
        GKI_enqueue (&(p_hci_cmd_cb->cmd_xmit_q), p_buf);
        p_buf = NULL;
    }

    /* Allow for startup case, where no acks may be received */
    if ( ((controller_id == LOCAL_BR_EDR_CONTROLLER_ID)
         && (p_hci_cmd_cb->cmd_window == 0)
         && (btm_cb.devcb.state == BTM_DEV_STATE_WAIT_RESET_CMPLT)) )
    {
        p_hci_cmd_cb->cmd_window = p_hci_cmd_cb->cmd_xmit_q.count + 1;
    }

    /* See if we can send anything */
    while (p_hci_cmd_cb->cmd_window != 0)
    {
        if (!p_buf)
            p_buf = (BT_HDR *)GKI_dequeue (&(p_hci_cmd_cb->cmd_xmit_q));

        if (p_buf)
        {
            btu_hcif_store_cmd(controller_id, p_buf);

#if ((L2CAP_HOST_FLOW_CTRL == TRUE)||defined(HCI_TESTER))
            pp = (UINT8 *)(p_buf + 1) + p_buf->offset;

            STREAM_TO_UINT16 (code, pp);

            /*
             * We do not need to decrease window for host flow control,
             * host flow control does not receive an event back from controller
             */
            if (code != HCI_HOST_NUM_PACKETS_DONE)
#endif
                p_hci_cmd_cb->cmd_window--;

            if (controller_id == LOCAL_BR_EDR_CONTROLLER_ID)
            {
                HCI_CMD_TO_LOWER(p_buf);
            }
            else
            {
                /* Unknown controller */
                BT_TRACE_1 (TRACE_LAYER_HCI, TRACE_TYPE_WARNING, "BTU HCI(ctrl id=%d) controller ID not recognized", controller_id);
                GKI_freebuf(p_buf);;
            }

            p_buf = NULL;
        }
        else
            break;
    }

    if (p_buf)
        GKI_enqueue (&(p_hci_cmd_cb->cmd_xmit_q), p_buf);

#if (defined(HCILP_INCLUDED) && HCILP_INCLUDED == TRUE)
    if (controller_id == LOCAL_BR_EDR_CONTROLLER_ID)
    {
        /* check if controller can go to sleep */
        btu_check_bt_sleep ();
    }
#endif

}


/*******************************************************************************
**
** Function         btu_hcif_send_host_rdy_for_data
**
** Description      This function is called to check if it can send commands
**                  to the Host Controller. It may be passed the address of
**                  a packet to send.
**
** Returns          void
**
*******************************************************************************/
void btu_hcif_send_host_rdy_for_data(void)
{
    UINT16      num_pkts[MAX_L2CAP_LINKS + 4];      /* 3 SCO connections */
    UINT16      handles[MAX_L2CAP_LINKS + 4];
    UINT8       num_ents;

    /* Get the L2CAP numbers */
    num_ents = l2c_link_pkts_rcvd (num_pkts, handles);

    /* Get the SCO numbers */
    /* No SCO for now ?? */

    if (num_ents)
    {
        btsnd_hcic_host_num_xmitted_pkts (num_ents, handles, num_pkts);
    }
}

/*******************************************************************************
**
** Function         btu_hcif_inquiry_comp_evt
**
** Description      Process event HCI_INQUIRY_COMP_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_inquiry_comp_evt (UINT8 *p, UINT16 evt_len)
{
    UINT8   status;

    STREAM_TO_UINT8    (status, p);

    /* Tell inquiry processing that we are done */
    btm_process_inq_complete(status, BTM_BR_INQUIRY_MASK);
}


/*******************************************************************************
**
** Function         btu_hcif_inquiry_result_evt
**
** Description      Process event HCI_INQUIRY_RESULT_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_inquiry_result_evt (UINT8 *p, UINT16 evt_len)
{
    /* Store results in the cache */
    btm_process_inq_results (p, BTM_INQ_RESULT_STANDARD);
}

/*******************************************************************************
**
** Function         btu_hcif_inquiry_rssi_result_evt
**
** Description      Process event HCI_INQUIRY_RSSI_RESULT_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_inquiry_rssi_result_evt (UINT8 *p, UINT16 evt_len)
{
    /* Store results in the cache */
    btm_process_inq_results (p, BTM_INQ_RESULT_WITH_RSSI);
}

/*******************************************************************************
**
** Function         btu_hcif_extended_inquiry_result_evt
**
** Description      Process event HCI_EXTENDED_INQUIRY_RESULT_EVT
**
** Returns          void
**
*******************************************************************************/
#if (BTM_EIR_CLIENT_INCLUDED == TRUE)
static void btu_hcif_extended_inquiry_result_evt (UINT8 *p, UINT16 evt_len)
{
    /* Store results in the cache */
    btm_process_inq_results (p, BTM_INQ_RESULT_EXTENDED);
}
#endif

/*******************************************************************************
**
** Function         btu_hcif_connection_comp_evt
**
** Description      Process event HCI_CONNECTION_COMP_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_connection_comp_evt (UINT8 *p, UINT16 evt_len)
{
    UINT8       status;
    UINT16      handle;
    BD_ADDR     bda;
    UINT8       link_type;
    UINT8       enc_mode;
#if BTM_SCO_INCLUDED == TRUE
    tBTM_ESCO_DATA  esco_data;
#endif

    STREAM_TO_UINT8    (status, p);
    STREAM_TO_UINT16   (handle, p);
    STREAM_TO_BDADDR   (bda, p);
    STREAM_TO_UINT8    (link_type, p);
    STREAM_TO_UINT8    (enc_mode, p);

    handle = HCID_GET_HANDLE (handle);

    if (link_type == HCI_LINK_TYPE_ACL)
    {
        btm_sec_connected (bda, handle, status, enc_mode);

        l2c_link_hci_conn_comp (status, handle, bda);
    }
#if BTM_SCO_INCLUDED == TRUE
    else
    {
        memset(&esco_data, 0, sizeof(tBTM_ESCO_DATA));
        /* esco_data.link_type = HCI_LINK_TYPE_SCO; already zero */
        memcpy (esco_data.bd_addr, bda, BD_ADDR_LEN);
        btm_sco_connected (status, bda, handle, &esco_data);
    }
#endif /* BTM_SCO_INCLUDED */
}


/*******************************************************************************
**
** Function         btu_hcif_connection_request_evt
**
** Description      Process event HCI_CONNECTION_REQUEST_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_connection_request_evt (UINT8 *p, UINT16 evt_len)
{
    BD_ADDR     bda;
    DEV_CLASS   dc;
    UINT8       link_type;

    STREAM_TO_BDADDR   (bda, p);
    STREAM_TO_DEVCLASS (dc, p);
    STREAM_TO_UINT8    (link_type, p);

    /* Pass request to security manager to check connect filters before */
    /* passing request to l2cap */
    if (link_type == HCI_LINK_TYPE_ACL)
    {
        btm_sec_conn_req (bda, dc);
    }
#if BTM_SCO_INCLUDED == TRUE
    else
    {
        btm_sco_conn_req (bda, dc, link_type);
    }
#endif /* BTM_SCO_INCLUDED */
}


/*******************************************************************************
**
** Function         btu_hcif_disconnection_comp_evt
**
** Description      Process event HCI_DISCONNECTION_COMP_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_disconnection_comp_evt (UINT8 *p, UINT16 evt_len)
{
    UINT8   status;
    UINT16  handle;
    UINT8   reason;

    STREAM_TO_UINT8  (status, p);
    STREAM_TO_UINT16 (handle, p);
    STREAM_TO_UINT8  (reason, p);

    handle = HCID_GET_HANDLE (handle);

#if BTM_SCO_INCLUDED == TRUE
    /* If L2CAP doesn't know about it, send it to SCO */
    if (!l2c_link_hci_disc_comp (handle, reason))
        btm_sco_removed (handle, reason);
#else
    l2c_link_hci_disc_comp (handle, reason);
#endif /* BTM_SCO_INCLUDED */

    /* Notify security manager */
    btm_sec_disconnected (handle, reason);
}

/*******************************************************************************
**
** Function         btu_hcif_authentication_comp_evt
**
** Description      Process event HCI_AUTHENTICATION_COMP_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_authentication_comp_evt (UINT8 *p, UINT16 evt_len)
{
    UINT8   status;
    UINT16  handle;

    STREAM_TO_UINT8  (status, p);
    STREAM_TO_UINT16 (handle, p);

    btm_sec_auth_complete (handle, status);
}


/*******************************************************************************
**
** Function         btu_hcif_rmt_name_request_comp_evt
**
** Description      Process event HCI_RMT_NAME_REQUEST_COMP_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_rmt_name_request_comp_evt (UINT8 *p, UINT16 evt_len)
{
    UINT8   status;
    BD_ADDR bd_addr;

    STREAM_TO_UINT8 (status, p);
    STREAM_TO_BDADDR (bd_addr, p);

    evt_len -= (1 + BD_ADDR_LEN);

    btm_process_remote_name (bd_addr, p, evt_len, status);

    btm_sec_rmt_name_request_complete (bd_addr, p, status);
}


/*******************************************************************************
**
** Function         btu_hcif_encryption_change_evt
**
** Description      Process event HCI_ENCRYPTION_CHANGE_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_encryption_change_evt (UINT8 *p, UINT16 evt_len)
{
    UINT8   status;
    UINT16  handle;
    UINT8   encr_enable;

    STREAM_TO_UINT8  (status, p);
    STREAM_TO_UINT16 (handle, p);
    STREAM_TO_UINT8  (encr_enable, p);

    btm_acl_encrypt_change (handle, status, encr_enable);
    btm_sec_encrypt_change (handle, status, encr_enable);
}


/*******************************************************************************
**
** Function         btu_hcif_change_conn_link_key_evt
**
** Description      Process event HCI_CHANGE_CONN_LINK_KEY_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_change_conn_link_key_evt (UINT8 *p, UINT16 evt_len)
{
    UINT8   status;
    UINT16  handle;

    STREAM_TO_UINT8  (status, p);
    STREAM_TO_UINT16 (handle, p);

    btm_acl_link_key_change (handle, status);
}


/*******************************************************************************
**
** Function         btu_hcif_master_link_key_comp_evt
**
** Description      Process event HCI_MASTER_LINK_KEY_COMP_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_master_link_key_comp_evt (UINT8 *p, UINT16 evt_len)
{
    UINT8   status;
    UINT16  handle;
    UINT8   key_flg;

    STREAM_TO_UINT8  (status, p);
    STREAM_TO_UINT16 (handle, p);
    STREAM_TO_UINT8  (key_flg, p);

    btm_sec_mkey_comp_event (handle, status, key_flg);
}


/*******************************************************************************
**
** Function         btu_hcif_read_rmt_features_comp_evt
**
** Description      Process event HCI_READ_RMT_FEATURES_COMP_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_read_rmt_features_comp_evt (UINT8 *p, UINT16 evt_len)
{
    btm_read_remote_features_complete(p);
}

/*******************************************************************************
**
** Function         btu_hcif_read_rmt_ext_features_comp_evt
**
** Description      Process event HCI_READ_RMT_EXT_FEATURES_COMP_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_read_rmt_ext_features_comp_evt (UINT8 *p, UINT16 evt_len)
{
    UINT8 *p_cur = p;
    UINT8 status;
    UINT16 handle;

    STREAM_TO_UINT8 (status, p_cur);

    if (status == HCI_SUCCESS)
        btm_read_remote_ext_features_complete(p);
    else
    {
        STREAM_TO_UINT16 (handle, p_cur);
        btm_read_remote_ext_features_failed(status, handle);
    }
}

/*******************************************************************************
**
** Function         btu_hcif_read_rmt_version_comp_evt
**
** Description      Process event HCI_READ_RMT_VERSION_COMP_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_read_rmt_version_comp_evt (UINT8 *p, UINT16 evt_len)
{
    btm_read_remote_version_complete (p);
}


/*******************************************************************************
**
** Function         btu_hcif_qos_setup_comp_evt
**
** Description      Process event HCI_QOS_SETUP_COMP_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_qos_setup_comp_evt (UINT8 *p, UINT16 evt_len)
{
    UINT8 status;
    UINT16 handle;
    FLOW_SPEC flow;

    STREAM_TO_UINT8 (status, p);
    STREAM_TO_UINT16 (handle, p);
    STREAM_TO_UINT8 (flow.qos_flags, p);
    STREAM_TO_UINT8 (flow.service_type, p);
    STREAM_TO_UINT32 (flow.token_rate, p);
    STREAM_TO_UINT32 (flow.peak_bandwidth, p);
    STREAM_TO_UINT32 (flow.latency, p);
    STREAM_TO_UINT32 (flow.delay_variation, p);

    btm_qos_setup_complete(status, handle, &flow);
}


/*******************************************************************************
**
** Function         btu_hcif_esco_connection_comp_evt
**
** Description      Process event HCI_ESCO_CONNECTION_COMP_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_esco_connection_comp_evt (UINT8 *p, UINT16 evt_len)
{
#if BTM_SCO_INCLUDED == TRUE
    tBTM_ESCO_DATA  data;
    UINT16          handle;
    BD_ADDR         bda;
    UINT8           status;

    STREAM_TO_UINT8 (status, p);
    STREAM_TO_UINT16 (handle, p);
    STREAM_TO_BDADDR (bda, p);

    STREAM_TO_UINT8 (data.link_type, p);
    STREAM_TO_UINT8 (data.tx_interval, p);
    STREAM_TO_UINT8 (data.retrans_window, p);
    STREAM_TO_UINT16 (data.rx_pkt_len, p);
    STREAM_TO_UINT16 (data.tx_pkt_len, p);
    STREAM_TO_UINT8 (data.air_mode, p);

    memcpy (data.bd_addr, bda, BD_ADDR_LEN);
    btm_sco_connected (status, bda, handle, &data);
#endif
}


/*******************************************************************************
**
** Function         btu_hcif_esco_connection_chg_evt
**
** Description      Process event HCI_ESCO_CONNECTION_CHANGED_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_esco_connection_chg_evt (UINT8 *p, UINT16 evt_len)
{
#if BTM_SCO_INCLUDED == TRUE
    UINT16  handle;
    UINT16  tx_pkt_len;
    UINT16  rx_pkt_len;
    UINT8   status;
    UINT8   tx_interval;
    UINT8   retrans_window;

    STREAM_TO_UINT8 (status, p);
    STREAM_TO_UINT16 (handle, p);

    STREAM_TO_UINT8 (tx_interval, p);
    STREAM_TO_UINT8 (retrans_window, p);
    STREAM_TO_UINT16 (rx_pkt_len, p);
    STREAM_TO_UINT16 (tx_pkt_len, p);

    btm_esco_proc_conn_chg (status, handle, tx_interval, retrans_window,
                            rx_pkt_len, tx_pkt_len);
#endif
}

/*******************************************************************************
**
** Function         btu_hcif_hdl_command_complete
**
** Description      Handle command complete event
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_hdl_command_complete (UINT16 opcode, UINT8 *p, UINT16 evt_len,
                                           void *p_cplt_cback, UINT8 ctr_id)
{
    switch (opcode)
    {
        case HCI_RESET:
            btm_reset_complete ();  /* BR/EDR */
            break;

        case HCI_INQUIRY_CANCEL:
            /* Tell inquiry processing that we are done */
            btm_process_cancel_complete(HCI_SUCCESS, BTM_BR_INQUIRY_MASK);
            break;
        case HCI_SET_EVENT_FILTER:
            btm_event_filter_complete (p);
            break;

        case HCI_READ_STORED_LINK_KEY:
            btm_read_stored_link_key_complete (p);
            break;

        case HCI_WRITE_STORED_LINK_KEY:
            btm_write_stored_link_key_complete (p);
            break;

        case HCI_DELETE_STORED_LINK_KEY:
            btm_delete_stored_link_key_complete (p);
            break;

        case HCI_READ_LOCAL_VERSION_INFO:
            btm_read_local_version_complete (p, evt_len);
            break;

        case HCI_READ_POLICY_SETTINGS:
            btm_read_link_policy_complete (p);
            break;

        case HCI_READ_BUFFER_SIZE:
            btm_read_hci_buf_size_complete (p, evt_len);
            break;

        case HCI_READ_LOCAL_SUPPORTED_CMDS:
            btm_read_local_supported_cmds_complete (p);
            break;

        case HCI_READ_LOCAL_FEATURES:
            btm_read_local_features_complete (p, evt_len);
            break;

        case HCI_READ_LOCAL_EXT_FEATURES:
            btm_read_local_ext_features_complete (p, evt_len);
            break;

        case HCI_READ_LOCAL_NAME:
            btm_read_local_name_complete (p, evt_len);
            break;

        case HCI_READ_BD_ADDR:
            btm_read_local_addr_complete (p, evt_len);
            break;

        case HCI_GET_LINK_QUALITY:
            btm_read_link_quality_complete (p);
            break;

        case HCI_READ_RSSI:
            btm_read_rssi_complete (p);
            break;

        case HCI_READ_TRANSMIT_POWER_LEVEL:
            btm_read_tx_power_complete(p, FALSE);
            break;

        case HCI_CREATE_CONNECTION_CANCEL:
            btm_create_conn_cancel_complete(p);
            break;

        case HCI_READ_LOCAL_OOB_DATA:
#if BTM_OOB_INCLUDED == TRUE
            btm_read_local_oob_complete(p);
#endif
            break;


        case HCI_READ_INQ_TX_POWER_LEVEL:
            btm_read_linq_tx_power_complete (p);
            break;

        case HCI_WRITE_SIMPLE_PAIRING_MODE:
            btm_write_simple_paring_mode_complete (p);
            break;

        case HCI_WRITE_LE_HOST_SUPPORTED:
            btm_write_le_host_supported_complete (p);
            break;

#if (BLE_INCLUDED == TRUE)
/* BLE Commands */
        case HCI_BLE_READ_WHITE_LIST_SIZE :
            btm_read_white_list_size_complete(p, evt_len);
            break;

        case HCI_BLE_ADD_WHITE_LIST:
            btm_ble_add_2_white_list_complete(*p);
            break;

        case HCI_BLE_CLEAR_WHITE_LIST:
            btm_ble_clear_white_list_complete(p, evt_len);
            break;

        case HCI_BLE_REMOVE_WHITE_LIST:
            btm_ble_remove_from_white_list_complete(p, evt_len);
            break;

        case HCI_BLE_RAND:
        case HCI_BLE_ENCRYPT:

            btm_ble_rand_enc_complete (p, opcode, (tBTM_RAND_ENC_CB *)p_cplt_cback);
            break;
        case HCI_BLE_READ_BUFFER_SIZE:
            btm_read_ble_buf_size_complete(p, evt_len);
            break;

        case HCI_BLE_READ_LOCAL_SPT_FEAT:
            btm_read_ble_local_supported_features_complete(p, evt_len);
            break;

        case HCI_BLE_READ_ADV_CHNL_TX_POWER:
            btm_read_tx_power_complete(p, TRUE);
            break;

        case HCI_BLE_WRITE_ADV_ENABLE:
            btm_ble_write_adv_enable_complete(p);
            break;

        case HCI_BLE_TRANSMITTER_TEST:
        case HCI_BLE_RECEIVER_TEST:
        case HCI_BLE_TEST_END:
            btm_ble_test_command_complete(p);
            break;
#endif /* (BLE_INCLUDED == TRUE) */

        default:
            if ((opcode & HCI_GRP_VENDOR_SPECIFIC) == HCI_GRP_VENDOR_SPECIFIC)
                btm_vsc_complete (p, opcode, evt_len, (tBTM_CMPL_CB *)p_cplt_cback);
            break;
    }
}

/*******************************************************************************
**
** Function         btu_hcif_command_complete_evt
**
** Description      Process event HCI_COMMAND_COMPLETE_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_command_complete_evt (UINT8 controller_id, UINT8 *p, UINT16 evt_len)
{
    tHCI_CMD_CB *p_hci_cmd_cb = &(btu_cb.hci_cmd_cb[controller_id]);
    UINT16      cc_opcode;
    BT_HDR      *p_cmd;
    void        *p_cplt_cback = NULL;

    STREAM_TO_UINT8  (p_hci_cmd_cb->cmd_window, p);

#if (defined(HCI_MAX_SIMUL_CMDS) && (HCI_MAX_SIMUL_CMDS > 0))
    if (p_hci_cmd_cb->cmd_window > HCI_MAX_SIMUL_CMDS)
        p_hci_cmd_cb->cmd_window = HCI_MAX_SIMUL_CMDS;
#endif

    STREAM_TO_UINT16 (cc_opcode, p);

    evt_len -= 3;

    /* only do this for certain commands */
    if ((cc_opcode != HCI_RESET) && (cc_opcode != HCI_HOST_NUM_PACKETS_DONE) &&
        (cc_opcode != HCI_COMMAND_NONE))
    {
        /* dequeue and free stored command */

/* always use cmd code check, when one cmd timeout waiting for cmd_cmpl,
   it'll cause the rest of the command goes in wrong order                  */
        p_cmd = (BT_HDR *) GKI_getfirst (&p_hci_cmd_cb->cmd_cmpl_q);

        while (p_cmd)
        {
            UINT16 opcode_dequeued;
            UINT8  *p_dequeued;

            /* Make sure dequeued command is for the command_cplt received */
            p_dequeued = (UINT8 *)(p_cmd + 1) + p_cmd->offset;
            STREAM_TO_UINT16 (opcode_dequeued, p_dequeued);

            if (opcode_dequeued != cc_opcode)
            {
                /* opcode does not match, check next command in the queue */
                p_cmd = (BT_HDR *) GKI_getnext(p_cmd);
                continue;
            }
            GKI_remove_from_queue(&p_hci_cmd_cb->cmd_cmpl_q, p_cmd);

            /* If command was a VSC, then extract command_complete callback */
            if ((cc_opcode & HCI_GRP_VENDOR_SPECIFIC) == HCI_GRP_VENDOR_SPECIFIC
#if BLE_INCLUDED == TRUE
                || (cc_opcode == HCI_BLE_RAND )
                || (cc_opcode == HCI_BLE_ENCRYPT)
#endif
               )
            {
                p_cplt_cback = *((void **)(p_cmd + 1));
            }

            GKI_freebuf (p_cmd);

            break;
        }

        /* if more commands in queue restart timer */
        if (BTU_CMD_CMPL_TIMEOUT > 0)
        {
            if (!GKI_queue_is_empty (&(p_hci_cmd_cb->cmd_cmpl_q)))
            {
#if (defined(BTU_CMD_CMPL_TOUT_DOUBLE_CHECK) && BTU_CMD_CMPL_TOUT_DOUBLE_CHECK == TRUE)
                p_hci_cmd_cb->checked_hcisu = FALSE;
#endif
                btu_start_timer (&(p_hci_cmd_cb->cmd_cmpl_timer),
                                 (UINT16)(BTU_TTYPE_BTU_CMD_CMPL + controller_id),
                                 BTU_CMD_CMPL_TIMEOUT);
            }
            else
            {
                btu_stop_timer (&(p_hci_cmd_cb->cmd_cmpl_timer));
            }
        }
    }

    /* handle event */
    btu_hcif_hdl_command_complete (cc_opcode, p, evt_len, p_cplt_cback, controller_id);

    /* see if we can send more commands */
    btu_hcif_send_cmd (controller_id, NULL);
}


/*******************************************************************************
**
** Function         btu_hcif_hdl_command_status
**
** Description      Handle a command status event
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_hdl_command_status (UINT16 opcode, UINT8 status, UINT8 *p_cmd,
                                         void *p_vsc_status_cback, UINT8 controller_id)
{
    BD_ADDR         bd_addr;
    UINT16          handle;
#if BTM_SCO_INCLUDED == TRUE
    tBTM_ESCO_DATA  esco_data;
#endif

#if BTM_PWR_MGR_INCLUDED == TRUE
    switch (opcode)
    {
        case HCI_EXIT_SNIFF_MODE:
        case HCI_EXIT_PARK_MODE:
#if BTM_SCO_WAKE_PARKED_LINK == TRUE
            if (status != HCI_SUCCESS)
            {
                /* Allow SCO initiation to continue if waiting for change mode event */
                if (p_cmd != NULL)
                {
                    p_cmd++;    /* bypass length field */
                    STREAM_TO_UINT16 (handle, p_cmd);
                    btm_sco_chk_pend_unpark (status, handle);
                }
            }
#endif
            /* Case Falls Through */

        case HCI_HOLD_MODE:
        case HCI_SNIFF_MODE:
        case HCI_PARK_MODE:
            btm_pm_proc_cmd_status(status);
            break;

        default:
#endif  /* BTM_PWR_MGR_INCLUDED */
            /* If command failed to start, we may need to tell BTM */
            if (status != HCI_SUCCESS)
            {
                switch (opcode)
                {
                    case HCI_INQUIRY:
                        /* Tell inquiry processing that we are done */
                        btm_process_inq_complete(status, BTM_BR_INQUIRY_MASK);
                        break;

                    case HCI_RMT_NAME_REQUEST:
                        /* Tell inquiry processing that we are done */
                        btm_process_remote_name (NULL, NULL, 0, status);

                        btm_sec_rmt_name_request_complete (NULL, NULL, status);
                        break;

                    case HCI_CHANGE_CONN_LINK_KEY:
                        /* Let host know we're done with error */
                        /* read handle out of stored command */
                        if (p_cmd != NULL)
                        {
                            p_cmd++;
                            STREAM_TO_UINT16 (handle, p_cmd);

                            btm_acl_link_key_change (handle, status);
                        }
                        break;

                    case HCI_QOS_SETUP_COMP_EVT:
                        /* Tell qos setup that we are done */
                        btm_qos_setup_complete(status,0,NULL);
                        break;

                    case HCI_SWITCH_ROLE:
                        /* Tell BTM that the command failed */
                        /* read bd addr out of stored command */
                        if (p_cmd != NULL)
                        {
                            p_cmd++;
                            STREAM_TO_BDADDR (bd_addr, p_cmd);
                            btm_acl_role_changed(status, bd_addr, BTM_ROLE_UNDEFINED);
                        }
                        else
                            btm_acl_role_changed(status, NULL, BTM_ROLE_UNDEFINED);
                        l2c_link_role_changed (NULL, BTM_ROLE_UNDEFINED, HCI_ERR_COMMAND_DISALLOWED);
                        break;

                    case HCI_CREATE_CONNECTION:
                        /* read bd addr out of stored command */
                        if (p_cmd != NULL)
                        {
                            p_cmd++;
                            STREAM_TO_BDADDR (bd_addr, p_cmd);
                            btm_sec_connected (bd_addr, HCI_INVALID_HANDLE, status, 0);
                            l2c_link_hci_conn_comp (status, HCI_INVALID_HANDLE, bd_addr);
                        }
                        break;

                    case HCI_READ_RMT_EXT_FEATURES:
                        if (p_cmd != NULL)
                        {
                            p_cmd++; /* skip command length */
                            STREAM_TO_UINT16 (handle, p_cmd);
                        }
                        else
                            handle = HCI_INVALID_HANDLE;

                        btm_read_remote_ext_features_failed(status, handle);
                        break;

                    case HCI_AUTHENTICATION_REQUESTED:
                        /* Device refused to start authentication.  That should be treated as authentication failure. */
                        btm_sec_auth_complete (BTM_INVALID_HCI_HANDLE, status);
                        break;

                    case HCI_SET_CONN_ENCRYPTION:
                        /* Device refused to start encryption.  That should be treated as encryption failure. */
                        btm_sec_encrypt_change (BTM_INVALID_HCI_HANDLE, status, FALSE);
                        break;

#if BTM_SCO_INCLUDED == TRUE
                    case HCI_SETUP_ESCO_CONNECTION:
                        /* read handle out of stored command */
                        if (p_cmd != NULL)
                        {
                            p_cmd++;
                            STREAM_TO_UINT16 (handle, p_cmd);

                            /* Determine if initial connection failed or is a change of setup */
                            if (btm_is_sco_active(handle))
                                btm_esco_proc_conn_chg (status, handle, 0, 0, 0, 0);
                            else
                                btm_sco_connected (status, NULL, handle, &esco_data);
                        }
                        break;
#endif

/* This is commented out until an upper layer cares about returning event
#if L2CAP_NON_FLUSHABLE_PB_INCLUDED == TRUE
            case HCI_ENHANCED_FLUSH:
                break;
#endif
*/
                    default:
                        if ((opcode & HCI_GRP_VENDOR_SPECIFIC) == HCI_GRP_VENDOR_SPECIFIC)
                            btm_vsc_complete (&status, opcode, 1, (tBTM_CMPL_CB *)p_vsc_status_cback);
                        break;
                }

            }
            else
            {
                if ((opcode & HCI_GRP_VENDOR_SPECIFIC) == HCI_GRP_VENDOR_SPECIFIC)
                    btm_vsc_complete (&status, opcode, 1, (tBTM_CMPL_CB *)p_vsc_status_cback);
            }
#if BTM_PWR_MGR_INCLUDED == TRUE
    }
#endif
}

/*******************************************************************************
**
** Function         btu_hcif_command_status_evt
**
** Description      Process event HCI_COMMAND_STATUS_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_command_status_evt (UINT8 controller_id, UINT8 *p, UINT16 evt_len)
{
    tHCI_CMD_CB * p_hci_cmd_cb = &(btu_cb.hci_cmd_cb[controller_id]);
    UINT8       status;
    UINT16      opcode;
    UINT16      cmd_opcode;
    BT_HDR      *p_cmd = NULL;
    UINT8       *p_data = NULL;
    void        *p_vsc_status_cback = NULL;

    STREAM_TO_UINT8  (status, p);
    STREAM_TO_UINT8  (p_hci_cmd_cb->cmd_window, p);

#if (defined(HCI_MAX_SIMUL_CMDS) && (HCI_MAX_SIMUL_CMDS > 0))
    if (p_hci_cmd_cb->cmd_window > HCI_MAX_SIMUL_CMDS)
        p_hci_cmd_cb->cmd_window = HCI_MAX_SIMUL_CMDS;
#endif

    STREAM_TO_UINT16 (opcode, p);

    /* only do this for certain commands */
    if ((opcode != HCI_RESET) && (opcode != HCI_HOST_NUM_PACKETS_DONE) &&
        (opcode != HCI_COMMAND_NONE))
    {
        /*look for corresponding command in cmd_queue*/
        p_cmd = (BT_HDR *) GKI_getfirst(&(p_hci_cmd_cb->cmd_cmpl_q));
        while (p_cmd)
        {
            p_data = (UINT8 *)(p_cmd + 1) + p_cmd->offset;
            STREAM_TO_UINT16 (cmd_opcode, p_data);

            /* Make sure this  command is for the command_status received */
            if (cmd_opcode != opcode)
            {
                /* opcode does not match, check next command in the queue */
                p_cmd = (BT_HDR *) GKI_getnext(p_cmd);
                continue;
            }
            else
            {
                GKI_remove_from_queue(&p_hci_cmd_cb->cmd_cmpl_q, p_cmd);

                /* If command was a VSC, then extract command_status callback */
                 if ((cmd_opcode & HCI_GRP_VENDOR_SPECIFIC) == HCI_GRP_VENDOR_SPECIFIC)
                {
                    p_vsc_status_cback = *((void **)(p_cmd + 1));
                }
                break;
            }
        }

        /* if more commands in queue restart timer */
        if (BTU_CMD_CMPL_TIMEOUT > 0)
        {
            if (!GKI_queue_is_empty (&(p_hci_cmd_cb->cmd_cmpl_q)))
            {
#if (defined(BTU_CMD_CMPL_TOUT_DOUBLE_CHECK) && BTU_CMD_CMPL_TOUT_DOUBLE_CHECK == TRUE)
                p_hci_cmd_cb->checked_hcisu = FALSE;
#endif
                btu_start_timer (&(p_hci_cmd_cb->cmd_cmpl_timer),
                                 (UINT16)(BTU_TTYPE_BTU_CMD_CMPL + controller_id),
                                 BTU_CMD_CMPL_TIMEOUT);
            }
            else
            {
                btu_stop_timer (&(p_hci_cmd_cb->cmd_cmpl_timer));
            }
        }
    }

    /* handle command */
    btu_hcif_hdl_command_status (opcode, status, p_data, p_vsc_status_cback, controller_id);

    /* free stored command */
    if (p_cmd != NULL)
    {
        GKI_freebuf (p_cmd);
    }
    else
    {
        BT_TRACE_1 (TRACE_LAYER_HCI, TRACE_TYPE_WARNING,
                    "No command in queue matching opcode %d", opcode);
    }

    /* See if we can forward any more commands */
    btu_hcif_send_cmd (controller_id, NULL);
}

/*******************************************************************************
**
** Function         btu_hcif_cmd_timeout
**
** Description      Handle a command timeout
**
** Returns          void
**
*******************************************************************************/
void btu_hcif_cmd_timeout (UINT8 controller_id)
{
    tHCI_CMD_CB * p_hci_cmd_cb = &(btu_cb.hci_cmd_cb[controller_id]);
    BT_HDR  *p_cmd;
    UINT8   *p;
    void    *p_cplt_cback = NULL;
    UINT16  opcode;
    UINT16  event;

#if (defined(BTU_CMD_CMPL_TOUT_DOUBLE_CHECK) && BTU_CMD_CMPL_TOUT_DOUBLE_CHECK == TRUE)
    if (!(p_hci_cmd_cb->checked_hcisu))
    {
        BT_TRACE_1 (TRACE_LAYER_HCI, TRACE_TYPE_WARNING, "BTU HCI(id=%d) command timeout - double check HCISU", controller_id);

        /* trigger HCISU to read any pending data in transport buffer */
        GKI_send_event(HCISU_TASK, HCISU_EVT_MASK);

        btu_start_timer (&(p_hci_cmd_cb->cmd_cmpl_timer),
                         (UINT16)(BTU_TTYPE_BTU_CMD_CMPL + controller_id),
                         2); /* start short timer, if timer is set to 1 then it could expire before HCISU checks. */

        p_hci_cmd_cb->checked_hcisu = TRUE;

        return;
    }
#endif

    /* set the controller cmd window to 1, as if we received a response, so
    ** the flow of commands from the stack doesn't hang */
    p_hci_cmd_cb->cmd_window = 1;

    /* get queued command */
    if ((p_cmd = (BT_HDR *) GKI_dequeue (&(p_hci_cmd_cb->cmd_cmpl_q))) == NULL)
    {
        BT_TRACE_0 (TRACE_LAYER_HCI, TRACE_TYPE_WARNING, "Cmd timeout; no cmd in queue");
        return;
    }

    /* if more commands in queue restart timer */
    if (BTU_CMD_CMPL_TIMEOUT > 0)
    {
        if (!GKI_queue_is_empty (&(p_hci_cmd_cb->cmd_cmpl_q)))
        {
#if (defined(BTU_CMD_CMPL_TOUT_DOUBLE_CHECK) && BTU_CMD_CMPL_TOUT_DOUBLE_CHECK == TRUE)
            p_hci_cmd_cb->checked_hcisu = FALSE;
#endif
            btu_start_timer (&(p_hci_cmd_cb->cmd_cmpl_timer),
                             (UINT16)(BTU_TTYPE_BTU_CMD_CMPL + controller_id),
                             BTU_CMD_CMPL_TIMEOUT);
        }
    }

    p = (UINT8 *)(p_cmd + 1) + p_cmd->offset;
#if (NFC_INCLUDED == TRUE)
    if (controller_id == NFC_CONTROLLER_ID)
    {
        //TODO call nfc_ncif_cmd_timeout
        BT_TRACE_2 (TRACE_LAYER_HCI, TRACE_TYPE_WARNING, "BTU NCI command timeout - header 0x%02x%02x", p[0], p[1]);
        return;
    }
#endif

    /* get opcode from stored command */
    STREAM_TO_UINT16 (opcode, p);

// btla-specific ++
#if (defined(ANDROID_APP_INCLUDED) && (ANDROID_APP_INCLUDED == TRUE))
    ALOGE("######################################################################");
    ALOGE("#");
    ALOGE("# WARNING : BTU HCI(id=%d) command timeout. opcode=0x%x", controller_id, opcode);
    ALOGE("#");
    ALOGE("######################################################################");
#else
    BT_TRACE_2 (TRACE_LAYER_HCI, TRACE_TYPE_WARNING, "BTU HCI(id=%d) command timeout. opcode=0x%x", controller_id, opcode);
#endif
// btla-specific ++

    /* send stack a fake command complete or command status, but first determine
    ** which to send
    */
    switch (opcode)
    {
        case HCI_HOLD_MODE:
        case HCI_SNIFF_MODE:
        case HCI_EXIT_SNIFF_MODE:
        case HCI_PARK_MODE:
        case HCI_EXIT_PARK_MODE:
        case HCI_INQUIRY:
        case HCI_RMT_NAME_REQUEST:
        case HCI_QOS_SETUP_COMP_EVT:
        case HCI_CREATE_CONNECTION:
        case HCI_CHANGE_CONN_LINK_KEY:
        case HCI_SWITCH_ROLE:
        case HCI_READ_RMT_EXT_FEATURES:
        case HCI_AUTHENTICATION_REQUESTED:
        case HCI_SET_CONN_ENCRYPTION:
#if BTM_SCO_INCLUDED == TRUE
        case HCI_SETUP_ESCO_CONNECTION:
#endif
            /* fake a command status */
            btu_hcif_hdl_command_status (opcode, HCI_ERR_UNSPECIFIED, p, NULL, controller_id);
            break;

        default:
            /* If vendor specific restore the callback function */
            if ((opcode & HCI_GRP_VENDOR_SPECIFIC) == HCI_GRP_VENDOR_SPECIFIC
#if BLE_INCLUDED == TRUE
                || (opcode == HCI_BLE_RAND ) ||
                (opcode == HCI_BLE_ENCRYPT)
#endif
               )
            {
                p_cplt_cback = *((void **)(p_cmd + 1));
#if 0
                BT_TRACE_2 (TRACE_LAYER_HCI, TRACE_TYPE_DEBUG,
                            "Restoring VSC callback for opcode=0x%04x, Callback function=0x%07x",
                            opcode, (UINT32)p_cplt_cback);
#endif
            }

            /* fake a command complete; first create a fake event */
            event = HCI_ERR_UNSPECIFIED;
            btu_hcif_hdl_command_complete (opcode, (UINT8 *)&event, 1, p_cplt_cback, controller_id);
            break;
    }

    /* free stored command */
    GKI_freebuf(p_cmd);

    num_hci_cmds_timed_out++;
    /* When we receive consecutive HCI cmd timeouts for >=BTM_MAX_HCI_CMD_TOUT_BEFORE_RESTART
     times, Bluetooth process will be killed and restarted */
    if (num_hci_cmds_timed_out >= BTM_MAX_HCI_CMD_TOUT_BEFORE_RESTART)
    {
        BT_TRACE_1(TRACE_LAYER_HCI, TRACE_TYPE_ERROR,
                  "Num consecutive HCI Cmd tout =%d Restarting BT process",num_hci_cmds_timed_out);
        bte_ssr_cleanup();
        usleep(10000); /* 10 milliseconds */
        /* Killing the process to force a restart as part of fault tolerance */
        kill(getpid(), SIGKILL);
    }
    else
    {
        BT_TRACE_1 (TRACE_LAYER_HCI, TRACE_TYPE_WARNING, "HCI Cmd timeout counter %d",
                    num_hci_cmds_timed_out);

        /* If anyone wants device status notifications, give him one */
        btm_report_device_status (BTM_DEV_STATUS_CMD_TOUT);
    }
    /* See if we can forward any more commands */
    btu_hcif_send_cmd (controller_id, NULL);
}

/*******************************************************************************
**
** Function         btu_hcif_hardware_error_evt
**
** Description      Process event HCI_HARDWARE_ERROR_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_hardware_error_evt (UINT8 *p, UINT16 evt_len)
{
    BT_TRACE_1 (TRACE_LAYER_HCI, TRACE_TYPE_ERROR, "Ctlr H/w error event - code:0x%x", *p);

    /* If anyone wants device status notifications, give him one. */
    btm_report_device_status (BTM_DEV_STATUS_DOWN);

    /* Reset the controller */
    if (BTM_IsDeviceUp())
        BTM_DeviceReset (NULL);
}


/*******************************************************************************
**
** Function         btu_hcif_flush_occured_evt
**
** Description      Process event HCI_FLUSH_OCCURED_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_flush_occured_evt (UINT8 *p, UINT16 evt_len)
{
}


/*******************************************************************************
**
** Function         btu_hcif_role_change_evt
**
** Description      Process event HCI_ROLE_CHANGE_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_role_change_evt (UINT8 *p, UINT16 evt_len)
{
    UINT8       status;
    BD_ADDR     bda;
    UINT8       role;

    STREAM_TO_UINT8 (status, p);
    STREAM_TO_BDADDR (bda, p);
    STREAM_TO_UINT8  (role, p);

    l2c_link_role_changed (bda, role, status);
    btm_acl_role_changed(status, bda, role);
}


/*******************************************************************************
**
** Function         btu_hcif_num_compl_data_pkts_evt
**
** Description      Process event HCI_NUM_COMPL_DATA_PKTS_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_num_compl_data_pkts_evt (UINT8 *p, UINT16 evt_len)
{
    /* Process for L2CAP and SCO */
    l2c_link_process_num_completed_pkts (p);

    /* Send on to SCO */
    /*?? No SCO for now */
}

/*******************************************************************************
**
** Function         btu_hcif_mode_change_evt
**
** Description      Process event HCI_MODE_CHANGE_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_mode_change_evt (UINT8 *p, UINT16 evt_len)
{
    UINT8       status;
    UINT16      handle;
    UINT8       current_mode;
    UINT16      interval;

    STREAM_TO_UINT8 (status, p);

    STREAM_TO_UINT16 (handle, p);
    STREAM_TO_UINT8 (current_mode, p);
    STREAM_TO_UINT16 (interval, p);
#if BTM_PWR_MGR_INCLUDED == TRUE
#if BTM_SCO_WAKE_PARKED_LINK == TRUE
    btm_sco_chk_pend_unpark (status, handle);
#endif
    btm_pm_proc_mode_change (status, handle, current_mode, interval);
#else
    btm_process_mode_change (status, handle, current_mode, interval);
#endif /* BTM_PWR_MGR_INCLUDED == TRUE */

#if (HID_DEV_INCLUDED == TRUE) && (HID_DEV_PM_INCLUDED == TRUE)
    hidd_pm_proc_mode_change( status, current_mode, interval ) ;
#endif
}

/*******************************************************************************
**
** Function         btu_hcif_ssr_evt
**
** Description      Process event HCI_SNIFF_SUB_RATE_EVT
**
** Returns          void
**
*******************************************************************************/
    #if (BTM_SSR_INCLUDED == TRUE)
static void btu_hcif_ssr_evt (UINT8 *p, UINT16 evt_len)
{
#if (BTM_PWR_MGR_INCLUDED == TRUE)
    btm_pm_proc_ssr_evt(p, evt_len);
#endif
}
    #endif


/*******************************************************************************
**
** Function         btu_hcif_return_link_keys_evt
**
** Description      Process event HCI_RETURN_LINK_KEYS_EVT
**
** Returns          void
**
*******************************************************************************/

static void btu_hcif_return_link_keys_evt (UINT8 *p, UINT16 evt_len)
{
    UINT8                       num_keys;
    tBTM_RETURN_LINK_KEYS_EVT   *result;

    /* get the number of link keys */
    num_keys = *p;

    /* If there are no link keys don't call the call back */
    if (!num_keys)
        return;

    /* Take one extra byte at the beginning to specify event */
    result = (tBTM_RETURN_LINK_KEYS_EVT *)(--p);
    result->event = BTM_CB_EVT_RETURN_LINK_KEYS;

    /* Call the BTM function to pass the link keys to application */
    btm_return_link_keys_evt (result);
}


/*******************************************************************************
**
** Function         btu_hcif_pin_code_request_evt
**
** Description      Process event HCI_PIN_CODE_REQUEST_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_pin_code_request_evt (UINT8 *p, UINT16 evt_len)
{
    BD_ADDR  bda;

    STREAM_TO_BDADDR (bda, p);

    /* Tell L2CAP that there was a PIN code request,  */
    /* it may need to stretch timeouts                */
    l2c_pin_code_request (bda);

    btm_sec_pin_code_request (bda);
}


/*******************************************************************************
**
** Function         btu_hcif_link_key_request_evt
**
** Description      Process event HCI_LINK_KEY_REQUEST_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_link_key_request_evt (UINT8 *p, UINT16 evt_len)
{
    BD_ADDR  bda;

    STREAM_TO_BDADDR (bda, p);
    btm_sec_link_key_request (bda);
}


/*******************************************************************************
**
** Function         btu_hcif_link_key_notification_evt
**
** Description      Process event HCI_LINK_KEY_NOTIFICATION_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_link_key_notification_evt (UINT8 *p, UINT16 evt_len)
{
    BD_ADDR  bda;
    LINK_KEY key;
    UINT8    key_type;

    STREAM_TO_BDADDR (bda, p);
    STREAM_TO_ARRAY16 (key, p);
    STREAM_TO_UINT8 (key_type, p);

    btm_sec_link_key_notification (bda, key, key_type);
}


/*******************************************************************************
**
** Function         btu_hcif_loopback_command_evt
**
** Description      Process event HCI_LOOPBACK_COMMAND_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_loopback_command_evt (UINT8 *p, UINT16 evt_len)
{
}


/*******************************************************************************
**
** Function         btu_hcif_data_buf_overflow_evt
**
** Description      Process event HCI_DATA_BUF_OVERFLOW_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_data_buf_overflow_evt (UINT8 *p, UINT16 evt_len)
{
}


/*******************************************************************************
**
** Function         btu_hcif_max_slots_changed_evt
**
** Description      Process event HCI_MAX_SLOTS_CHANGED_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_max_slots_changed_evt (UINT8 *p, UINT16 evt_len)
{
}


/*******************************************************************************
**
** Function         btu_hcif_read_clock_off_comp_evt
**
** Description      Process event HCI_READ_CLOCK_OFF_COMP_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_read_clock_off_comp_evt (UINT8 *p, UINT16 evt_len)
{
    UINT8       status;
    UINT16      handle;
    UINT16      clock_offset;

    STREAM_TO_UINT8  (status, p);

    /* If failed to get clock offset just drop the result */
    if (status != HCI_SUCCESS)
        return;

    STREAM_TO_UINT16 (handle, p);
    STREAM_TO_UINT16 (clock_offset, p);

    handle = HCID_GET_HANDLE (handle);

    btm_process_clk_off_comp_evt (handle, clock_offset);
    btm_sec_update_clock_offset (handle, clock_offset);
}


/*******************************************************************************
**
** Function         btu_hcif_conn_pkt_type_change_evt
**
** Description      Process event HCI_CONN_PKT_TYPE_CHANGE_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_conn_pkt_type_change_evt (UINT8 *p, UINT16 evt_len)
{
}


/*******************************************************************************
**
** Function         btu_hcif_qos_violation_evt
**
** Description      Process event HCI_QOS_VIOLATION_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_qos_violation_evt (UINT8 *p, UINT16 evt_len)
{
    UINT16   handle;

    STREAM_TO_UINT16 (handle, p);

    handle = HCID_GET_HANDLE (handle);


    l2c_link_hci_qos_violation (handle);
}


/*******************************************************************************
**
** Function         btu_hcif_page_scan_mode_change_evt
**
** Description      Process event HCI_PAGE_SCAN_MODE_CHANGE_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_page_scan_mode_change_evt (UINT8 *p, UINT16 evt_len)
{
}


/*******************************************************************************
**
** Function         btu_hcif_page_scan_rep_mode_chng_evt
**
** Description      Process event HCI_PAGE_SCAN_REP_MODE_CHNG_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_page_scan_rep_mode_chng_evt (UINT8 *p, UINT16 evt_len)
{
}

/**********************************************
** Simple Pairing Events
***********************************************/

/*******************************************************************************
**
** Function         btu_hcif_host_support_evt
**
** Description      Process event HCI_RMT_HOST_SUP_FEAT_NOTIFY_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_host_support_evt (UINT8 *p, UINT16 evt_len)
{
    btm_sec_rmt_host_support_feat_evt(p);
}

/*******************************************************************************
**
** Function         btu_hcif_io_cap_request_evt
**
** Description      Process event HCI_IO_CAPABILITY_REQUEST_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_io_cap_request_evt (UINT8 *p, UINT16 evt_len)
{
    btm_io_capabilities_req(p);
}


/*******************************************************************************
**
** Function         btu_hcif_io_cap_response_evt
**
** Description      Process event HCI_IO_CAPABILITY_RESPONSE_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_io_cap_response_evt (UINT8 *p, UINT16 evt_len)
{
    btm_io_capabilities_rsp(p);
}


/*******************************************************************************
**
** Function         btu_hcif_user_conf_request_evt
**
** Description      Process event HCI_USER_CONFIRMATION_REQUEST_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_user_conf_request_evt (UINT8 *p, UINT16 evt_len)
{
    btm_proc_sp_req_evt(BTM_SP_CFM_REQ_EVT, p);
}


/*******************************************************************************
**
** Function         btu_hcif_user_passkey_request_evt
**
** Description      Process event HCI_USER_PASSKEY_REQUEST_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_user_passkey_request_evt (UINT8 *p, UINT16 evt_len)
{
    btm_proc_sp_req_evt(BTM_SP_KEY_REQ_EVT, p);
}

/*******************************************************************************
**
** Function         btu_hcif_user_passkey_notif_evt
**
** Description      Process event HCI_USER_PASSKEY_NOTIFY_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_user_passkey_notif_evt (UINT8 *p, UINT16 evt_len)
{
    btm_proc_sp_req_evt(BTM_SP_KEY_NOTIF_EVT, p);
}

/*******************************************************************************
**
** Function         btu_hcif_keypress_notif_evt
**
** Description      Process event HCI_KEYPRESS_NOTIFY_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_keypress_notif_evt (UINT8 *p, UINT16 evt_len)
{
    btm_keypress_notif_evt(p);
}

/*******************************************************************************
**
** Function         btu_hcif_link_super_tout_evt
**
** Description      Process event HCI_LINK_SUPER_TOUT_CHANGED_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_link_super_tout_evt (UINT8 *p, UINT16 evt_len)
{
    UINT16 handle, timeout;
    STREAM_TO_UINT16 (handle, p);
    STREAM_TO_UINT16 (timeout, p);

    btm_proc_lsto_evt(handle, timeout);
}

/*******************************************************************************
**
** Function         btu_hcif_rem_oob_request_evt
**
** Description      Process event HCI_REMOTE_OOB_DATA_REQUEST_EVT
**
** Returns          void
**
*******************************************************************************/
    #if BTM_OOB_INCLUDED == TRUE
static void btu_hcif_rem_oob_request_evt (UINT8 *p, UINT16 evt_len)
{
    btm_rem_oob_req(p);
}
    #endif

/*******************************************************************************
**
** Function         btu_hcif_simple_pair_complete_evt
**
** Description      Process event HCI_SIMPLE_PAIRING_COMPLETE_EVT
**
** Returns          void
**
*******************************************************************************/
static void btu_hcif_simple_pair_complete_evt (UINT8 *p, UINT16 evt_len)
{
    btm_simple_pair_complete(p);
}
/*******************************************************************************
**
** Function         btu_hcif_flush_cmd_queue
**
** Description      Flush the HCI command complete queue and transmit queue when
**                  needed.
**
** Returns          void
**
*******************************************************************************/
void btu_hcif_flush_cmd_queue(void)
{
    BT_HDR *p_cmd;

    btu_cb.hci_cmd_cb[0].cmd_window = 0;
    while ((p_cmd = (BT_HDR *) GKI_dequeue (&btu_cb.hci_cmd_cb[0].cmd_cmpl_q)) != NULL)
    {
        GKI_freebuf (p_cmd);
    }
    while ((p_cmd = (BT_HDR *) GKI_dequeue (&btu_cb.hci_cmd_cb[0].cmd_xmit_q)) != NULL)
    {
        GKI_freebuf (p_cmd);
    }
}

/*******************************************************************************
**
** Function         btu_hcif_enhanced_flush_complete_evt
**
** Description      Process event HCI_ENHANCED_FLUSH_COMPLETE_EVT
**
** Returns          void
**
*******************************************************************************/
#if L2CAP_NON_FLUSHABLE_PB_INCLUDED == TRUE
static void btu_hcif_enhanced_flush_complete_evt (UINT8 *p, UINT16 evt_len)
{
/* This is empty until an upper layer cares about returning event */
}
#endif
/**********************************************
** End of Simple Pairing Events
***********************************************/


/**********************************************
** BLE Events
***********************************************/
#if (defined BLE_INCLUDED) && (BLE_INCLUDED == TRUE)
static void btu_hcif_encyption_key_refresh_cmpl_evt (UINT8 *p, UINT16 evt_len)
{
    UINT8   status;
    UINT8   enc_enable = 0;
    UINT16  handle;

    STREAM_TO_UINT8  (status, p);
    STREAM_TO_UINT16 (handle, p);

    if (status == HCI_SUCCESS) enc_enable = 1;

    btm_sec_encrypt_change (handle, status, enc_enable);
}

static void btu_ble_process_adv_pkt (UINT8 *p, UINT16 evt_len)
{
    BT_TRACE_0 (TRACE_LAYER_HCI, TRACE_TYPE_EVENT, "btu_ble_process_adv_pkt");

    btm_ble_process_adv_pkt(p);
}

static void btu_ble_ll_conn_complete_evt ( UINT8 *p, UINT16 evt_len)
{
    btm_ble_conn_complete(p, evt_len);
}

static void btu_ble_ll_conn_param_upd_evt (UINT8 *p, UINT16 evt_len)
{
/* This is empty until an upper layer cares about returning event */
    //LE connection update has completed successfully as a master.
    //We can enable the update request if the result is a success
    //extract the HCI handle first
    UINT8   status;
    UINT16  handle;
    BT_TRACE_0(TRACE_LAYER_HCI, TRACE_TYPE_EVENT, "btu_ble_ll_conn_param_upd_evt");

    STREAM_TO_UINT8  (status, p);
    STREAM_TO_UINT16 (handle, p);
    L2CA_HandleConnUpdateEvent(handle, status);
}

static void btu_ble_ll_conn_param_req_evt (UINT8 *p, UINT16 evt_len)
{
    UINT16  handle;
    UINT16 conn_interval_min;
    UINT16 conn_interval_max;
    UINT16 latency;
    UINT16 timeout;
    UINT8 is_positive_reply = 1;

    BT_TRACE_0(TRACE_LAYER_HCI, TRACE_TYPE_EVENT, "btu_ble_ll_conn_param_req_evt");

    STREAM_TO_UINT16 (handle, p);
    STREAM_TO_UINT16 (conn_interval_min, p);
    STREAM_TO_UINT16 (conn_interval_max, p);
    STREAM_TO_UINT16 (latency, p);
    STREAM_TO_UINT16 (timeout, p);


    if(is_positive_reply)
        btsnd_hcic_ble_remote_conn_params_request_reply(handle, conn_interval_min, conn_interval_max,
                latency, timeout, 0, 0);
    else
        btsnd_hcic_ble_remote_conn_params_request_negative_reply(handle, HCI_ERR_UNACCEPT_CONN_INTERVAL);

}

static void btu_ble_read_remote_feat_evt (UINT8 *p, UINT16 evt_len)
{
    btm_ble_read_remote_features_complete(p);
}

static void btu_ble_proc_ltk_req (UINT8 *p, UINT16 evt_len)
{
    UINT16 ediv, handle;
    UINT8   *pp;

    STREAM_TO_UINT16(handle, p);
    pp = p + 8;
    STREAM_TO_UINT16(ediv, pp);
#if BLE_INCLUDED == TRUE && SMP_INCLUDED == TRUE
    btm_ble_ltk_request(handle, p, ediv);
#endif
    /* This is empty until an upper layer cares about returning event */
}
/**********************************************
** End of BLE Events Handler
***********************************************/
#endif /* BLE_INCLUDED */

