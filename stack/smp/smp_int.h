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
 *  This file contains internally used SMP definitions
 *
 ******************************************************************************/

#ifndef  SMP_INT_H
#define  SMP_INT_H

#include "btu.h"
#include "smp_api.h"

#define SMP_MODEL_ENC_ONLY  0
#define SMP_MODEL_PASSKEY   1
#define SMP_MODEL_OOB       2
#define SMP_MODEL_KEY_NOTIF 3
#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
#define SMP_MODEL_NUM_COMP  4
#define SMP_MODEL_MAX       5
#else
#define SMP_MODEL_MAX       4
#endif

typedef UINT8   tSMP_ASSO_MODEL;


#ifndef SMP_MAX_CONN
    #define SMP_MAX_CONN    2
#endif

#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
#define SMP_SEC_REPEAT_COUNT    20
#endif

#define SMP_WAIT_FOR_RSP_TOUT			30
#define SMP_WAIT_FOR_REL_DELAY_TOUT     2
/* SMP L2CAP command code */
#define SMP_OPCODE_PAIRING_REQ            0x01
#define SMP_OPCODE_PAIRING_RSP            0x02
#define SMP_OPCODE_CONFIRM                0x03
#define SMP_OPCODE_INIT                   0x04
#define SMP_OPCODE_PAIRING_FAILED         0x05
#define SMP_OPCODE_ENCRYPT_INFO           0x06
#define SMP_OPCODE_MASTER_ID              0x07
#define SMP_OPCODE_IDENTITY_INFO          0x08
#define SMP_OPCODE_ID_ADDR                0x09
#define SMP_OPCODE_SIGN_INFO              0x0A
#define SMP_OPCODE_SEC_REQ                0x0B
#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
#define SMP_OPCODE_PUBLIC_KEY             0x0C
#define SMP_OPCODE_DHKEY_CHECK            0x0D
#define SMP_OPCODE_KEYPRESS_NOT           0x0E
#endif

#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
#define SMP_OPCODE_MAX                    (SMP_OPCODE_KEYPRESS_NOT + 1)
#else
#define SMP_OPCODE_MAX                    (SMP_OPCODE_SEC_REQ + 1)
#endif

/* SMP events */
#define SMP_PAIRING_REQ_EVT             SMP_OPCODE_PAIRING_REQ
#define SMP_PAIRING_RSP_EVT             SMP_OPCODE_PAIRING_RSP
#define SMP_CONFIRM_EVT                 SMP_OPCODE_CONFIRM
#define SMP_RAND_EVT                    SMP_OPCODE_INIT
#define SMP_PAIRING_FAILED_EVT          SMP_OPCODE_PAIRING_FAILED
#define SMP_ENCRPTION_INFO_EVT          SMP_OPCODE_ENCRYPT_INFO
#define SMP_MASTER_ID_EVT               SMP_OPCODE_MASTER_ID
#define SMP_ID_INFO_EVT                 SMP_OPCODE_IDENTITY_INFO
#define SMP_ID_ADDR_EVT                 SMP_OPCODE_ID_ADDR
#define SMP_SIGN_INFO_EVT               SMP_OPCODE_SIGN_INFO
#define SMP_SECURITY_REQ_EVT            SMP_OPCODE_SEC_REQ

#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
#define SMP_REMOTE_PUBLIC_KEY_EVT       SMP_OPCODE_PUBLIC_KEY
#define SMP_REMOTE_DHKEY_EVT            SMP_OPCODE_DHKEY_CHECK
#define SMP_KEY_PRESS_NOT_EVT           SMP_OPCODE_KEYPRESS_NOT
#endif

#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
#define SMP_SELF_DEF_EVT                SMP_OPCODE_KEYPRESS_NOT
#else
#define SMP_SELF_DEF_EVT                SMP_SECURITY_REQ_EVT
#endif

#define SMP_KEY_READY_EVT               (SMP_SELF_DEF_EVT + 1)
#define SMP_ENCRYPTED_EVT               (SMP_SELF_DEF_EVT + 2)
#define SMP_L2CAP_CONN_EVT              (SMP_SELF_DEF_EVT + 3)
#define SMP_L2CAP_DISCONN_EVT           (SMP_SELF_DEF_EVT + 4)
#define SMP_IO_RSP_EVT                  (SMP_SELF_DEF_EVT + 5)
#define SMP_API_SEC_GRANT_EVT           (SMP_SELF_DEF_EVT + 6)
#define SMP_TK_REQ_EVT                  (SMP_SELF_DEF_EVT + 7)
#define SMP_AUTH_CMPL_EVT               (SMP_SELF_DEF_EVT + 8)
#define SMP_ENC_REQ_EVT                 (SMP_SELF_DEF_EVT + 9)
#define SMP_BOND_REQ_EVT                (SMP_SELF_DEF_EVT + 10)
#define SMP_DISCARD_SEC_REQ_EVT         (SMP_SELF_DEF_EVT + 11)
#define SMP_RELEASE_DELAY_EVT           (SMP_SELF_DEF_EVT + 12)
#define SMP_RELEASE_DELAY_TOUT_EVT      (SMP_SELF_DEF_EVT + 13)
#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
#define SMP_DH_KEY_EVT                  (SMP_SELF_DEF_EVT + 14)
#define SMP_API_PASSKEY_CONF_EVT        (SMP_SELF_DEF_EVT + 15)
#define SMP_INIT_SECURE_CONN_EVT        (SMP_SELF_DEF_EVT + 16)
#define SMP_PUB_KEY_SENT_EVT            (SMP_SELF_DEF_EVT + 17)
#define SMP_CONFIRM_REPEAT_EVT          (SMP_SELF_DEF_EVT + 18)
#define SMP_LOCAL_KEYPRESS_EVT          (SMP_SELF_DEF_EVT + 19)
#endif
typedef UINT8 tSMP_EVENT;
#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
#define SMP_MAX_EVT         SMP_LOCAL_KEYPRESS_EVT + 1
#else
#define SMP_MAX_EVT         SMP_RELEASE_DELAY_TOUT_EVT + 1
#endif

/* SMP pairing state */
enum
{
    SMP_ST_IDLE,
    SMP_ST_WAIT_APP_RSP,
    SMP_ST_SEC_REQ_PENDING,
    SMP_ST_PAIR_REQ_RSP,
    SMP_ST_WAIT_CONFIRM,
    SMP_ST_CONFIRM,
    SMP_ST_RAND,
    SMP_ST_ENC_PENDING,
    SMP_ST_BOND_PENDING,
    SMP_ST_RELEASE_DELAY,
#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
    SMP_ST_WAIT_PUB_KEY,
    SMP_ST_WAIT_NONCE,
    SMP_ST_WAIT_SC_CONFIRM,
    SMP_ST_COMMIT,
    SMP_ST_DERIVE_LTK,
#endif
    SMP_ST_MAX
};
typedef UINT8 tSMP_STATE;

/* random and encrption activity state */
enum
{
    SMP_GEN_COMPARE = 1,
    SMP_GEN_CONFIRM,

    SMP_GEN_DIV_LTK,
    SMP_GEN_DIV_CSRK,
    SMP_GEN_RAND_V,
    SMP_GEN_TK,
    SMP_GEN_SRAND_MRAND,
    SMP_GEN_SRAND_MRAND_CONT
};

enum
{
    SMP_KEY_TYPE_TK,
    SMP_KEY_TYPE_CFM,
    SMP_KEY_TYPE_CMP,
    SMP_KEY_TYPE_STK,
    SMP_KEY_TYPE_LTK
#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
    ,
    SMP_KEY_TYPE_COMMIT,
    SMP_KEY_TYPE_SC_CFM
#endif
};
typedef struct
{
    UINT8   key_type;
    UINT8*  p_data;
}tSMP_KEY;

typedef union
{
    UINT8       *p_data;    /* UINT8 type data pointer */
    tSMP_KEY    key;
    UINT16      reason;
}tSMP_INT_DATA;

/* internal status mask */
#define SMP_PAIR_FLAGS_WE_STARTED_DD           (1)
#define SMP_PAIR_FLAGS_PEER_STARTED_DD         (1 << 1)
#define SMP_PAIR_FLAGS_CMD_CONFIRM             (1 << SMP_OPCODE_CONFIRM) /* 1 << 3 */
#define SMP_PAIR_FLAG_ENC_AFTER_PAIR           (1 << 4)
#define SMP_PAIR_FLAGS_CMD_COMMIT              (1 << 5)
#define SMP_PAIR_FLAGS_MACKEY_COMP             (1 << 6)
#define SMP_PAIR_FLAGS_CMD_INIT                (1 << 7)

/* check if authentication requirement need MITM protection */
#define SMP_NO_MITM_REQUIRED(x)  (((x) & SMP_AUTH_YN_BIT) == 0)

#define SMP_ENCRYT_KEY_SIZE                16
#define SMP_ENCRYT_DATA_SIZE               16
#define SMP_ECNCRPYT_STATUS                HCI_SUCCESS

/* SMP control block */
typedef struct
{
    tSMP_CALLBACK   *p_callback;
    TIMER_LIST_ENT  rsp_timer_ent;
    UINT8           trace_level;

    BD_ADDR         pairing_bda;

    tSMP_STATE      state;
    UINT8           failure;
    UINT8           status;
    UINT8           role;
    UINT8           flags;
    UINT8           cb_evt;

    tSMP_SEC_LEVEL  sec_level;
    BOOLEAN         connect_initialized;
    BT_OCTET16      confirm;
    BT_OCTET16      rconfirm;
    BT_OCTET16      rrand;
    BT_OCTET16      rand;
    tSMP_IO_CAP     peer_io_caps;
    tSMP_IO_CAP     loc_io_caps;
    tSMP_OOB_FLAG   peer_oob_flag;
    tSMP_OOB_FLAG   loc_oob_flag;
    tSMP_AUTH_REQ   peer_auth_req;
    tSMP_AUTH_REQ   loc_auth_req;
    UINT8           peer_enc_size;
    UINT8           loc_enc_size;
    UINT8           peer_i_key;
    UINT8           peer_r_key;
    UINT8           loc_i_key;
    UINT8           loc_r_key;

    BT_OCTET16      tk;
    BT_OCTET16      ltk;
    UINT16          div;
    BT_OCTET16      csrk;  /* storage for local CSRK */
    UINT16          ediv;
    BT_OCTET8       enc_rand;

    UINT8           rand_enc_proc;
    BOOLEAN         last_cmd;
    UINT8           addr_type;
    BD_ADDR         local_bda;
    BOOLEAN         is_pair_cancel;
    BOOLEAN         discard_sec_req;
    UINT8           rcvd_cmd_code;
    UINT8           rcvd_cmd_len;
#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
    BOOLEAN         is_secure;
    BT_OCTET32      dhkey;
    BOOLEAN         dhk_recvd;
    BT_OCTET64      rem_pub_key;
    BT_OCTET16      mackey;
    BT_OCTET16      commit;
    BT_OCTET16      rcommit;
    tSMP_ASSO_MODEL model;
    UINT8           confirm_counter;
    UINT8           notification;
    BT_OCTET16      link_key;
    BT_OCTET16      loob;
    BT_OCTET16      roob;
    BOOLEAN         smp_bredr;
    BD_ADDR         private_addr;
#endif
#if SMP_CONFORMANCE_TESTING == TRUE
    BOOLEAN         enable_test_confirm_val;
    BT_OCTET16      test_confirm;
    BOOLEAN         enable_test_rand_val;
    BT_OCTET16      test_rand;
    BOOLEAN         enable_test_pair_fail;
    UINT8           pair_fail_status;
    BOOLEAN         remove_fixed_channel_disable;
    BOOLEAN         skip_test_compare_check;
#endif

}tSMP_CB;

/* Server Action functions are of this type */
typedef void (*tSMP_ACT)(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);


#ifdef __cplusplus
extern "C"
{
#endif

#if SMP_DYNAMIC_MEMORY == FALSE
    SMP_API extern tSMP_CB  smp_cb;
#else
    SMP_API extern tSMP_CB *smp_cb_ptr;
#define smp_cb (*smp_cb_ptr)
#endif

#ifdef __cplusplus
}
#endif

/* Functions provided by att_main.c */
SMP_API extern void smp_init (void);

#if SMP_CONFORMANCE_TESTING == TRUE
/* Used only for conformance testing */
SMP_API extern void  smp_set_test_confirm_value (BOOLEAN enable, UINT8 *p_c_value);
SMP_API extern void  smp_set_test_rand_value (BOOLEAN enable, UINT8 *p_c_value);
SMP_API extern void  smp_set_test_pair_fail_status (BOOLEAN enable, UINT8 status);
SMP_API extern void  smp_remove_fixed_channel_disable (BOOLEAN disable);
SMP_API extern void  smp_skip_compare_check (BOOLEAN enable);
#endif
/* smp main */
extern void smp_sm_event(tSMP_CB *p_cb, tSMP_EVENT event, void *p_data);

extern void smp_proc_sec_request(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_send_pair_req(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_send_confirm(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_send_pair_fail(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_send_init(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_sec_request(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_pair_fail(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_confirm(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_init(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_enc_info(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_master_id(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_id_info(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_id_addr(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_sec_grant(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_sec_req(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_sl_key(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_start_enc(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_enc_cmpl(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_discard(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_release_delay(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_release_delay_tout(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_pairing_cmpl(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_decide_asso_model(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_send_app_cback(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_compare(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_check_auth_req(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_io_rsp(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_send_id_info(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_send_enc_info(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_send_csrk_info(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_send_ltk_reply(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_pair_cmd(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_pair_terminate(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_idle_terminate(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_send_pair_rsp(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_key_distribution(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_srk_info(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_generate_csrk(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_delay_terminate(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_fast_conn_param(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);

/* smp_l2c */
extern void smp_l2cap_if_init (void);

/* smp utility */
extern BOOLEAN smp_send_cmd(UINT8 cmd_code, tSMP_CB *p_cb);
extern void smp_cb_cleanup(tSMP_CB *p_cb);
extern void smp_reset_control_value(tSMP_CB *p_cb);
extern void smp_proc_pairing_cmpl(tSMP_CB *p_cb);
extern void smp_convert_string_to_tk(BT_OCTET16 tk, UINT32 passkey);
extern void smp_mask_enc_key(UINT8 loc_enc_size, UINT8 * p_data);
extern void smp_rsp_timeout(TIMER_LIST_ENT *p_tle);
extern void smp_xor_128(BT_OCTET16 a, BT_OCTET16 b);
extern BOOLEAN smp_encrypt_data (UINT8 *key, UINT8 key_len,
                                 UINT8 *plain_text, UINT8 pt_len,
                                 tSMP_ENC *p_out);
/* smp key */
extern void smp_generate_confirm (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_generate_compare (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_generate_stk (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_generate_ltk(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_generate_passkey (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_genenrate_rand_cont(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);

/* smp main util */
extern void smp_set_state(tSMP_STATE state);
extern tSMP_STATE smp_get_state(void);
extern void smp_reject_unexp_pair_req(BD_ADDR bd_addr);

#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
extern void smp_generate_dhkey (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_send_public_key (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_public_key (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_generate_nonce (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_generate_sc_confirm (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_verify_sc_confirm (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_generate_verifier (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_compute_commit (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_compute_sc_ltk (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_send_commit (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_process_commit (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_model_spec_action (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_send_keypress_notification (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_proc_keypress_notification (tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern BOOLEAN smp_verify_oob_confirm (tSMP_CB *p_cb);
extern void smp_derive_LTK(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
extern void smp_generate_rpa(tSMP_CB *p_cb, BT_OCTET16 rem_irk);
#endif

#endif /* SMP_INT_H */

