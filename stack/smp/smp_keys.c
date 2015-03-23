/******************************************************************************
 *
 *  Copyright (C) 2008-2012 Broadcom Corporation
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
 *  This file contains the implementation of the SMP utility functions used
 *  by SMP.
 *
 ******************************************************************************/

#include "bt_target.h"
#include "bt_utils.h"

#if SMP_INCLUDED == TRUE
    #if SMP_DEBUG == TRUE
        #include <stdio.h>
    #endif
    #include <string.h>

    #include "btm_ble_api.h"
    #include "smp_int.h"
    #include "btm_int.h"
    #include "btm_ble_int.h"
    #include "hcimsgs.h"
    #include "aes.h"
    #ifndef SMP_MAX_ENC_REPEAT
        #define SMP_MAX_ENC_REPEAT      3
    #endif

static void smp_rand_back(tBTM_RAND_ENC *p);
static void smp_genenrate_confirm(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
static void smp_genenrate_ltk_cont(tSMP_CB *p_cb, tSMP_INT_DATA *p_data);
static void smp_generate_y(tSMP_CB *p_cb, tSMP_INT_DATA *p);
static void smp_generate_rand_vector (tSMP_CB *p_cb, tSMP_INT_DATA *p);
static void smp_process_stk(tSMP_CB *p_cb, tSMP_ENC *p);
static void smp_calculate_comfirm_cont(tSMP_CB *p_cb, tSMP_ENC *p);
static void smp_process_confirm(tSMP_CB *p_cb, tSMP_ENC *p);
static void smp_process_compare(tSMP_CB *p_cb, tSMP_ENC *p);
static void smp_process_ediv(tSMP_CB *p_cb, tSMP_ENC *p);
#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
static void smp_generate_mackey(tSMP_CB *p_cb, tSMP_INT_DATA *p_data, UINT8 counter);
#endif

static const tSMP_ACT smp_encrypt_action[] =
{
    smp_generate_compare,           /* SMP_GEN_COMPARE */
    smp_genenrate_confirm,          /* SMP_GEN_CONFIRM*/
    smp_generate_stk,               /* SMP_GEN_STK*/
    smp_genenrate_ltk_cont,          /* SMP_GEN_LTK */
    smp_generate_ltk,               /* SMP_GEN_DIV_LTK */
    smp_generate_rand_vector,        /* SMP_GEN_RAND_V */
    smp_generate_y,                  /* SMP_GEN_EDIV */
    smp_generate_passkey,           /* SMP_GEN_TK */
    smp_generate_confirm,           /* SMP_GEN_SRAND_MRAND */
    smp_genenrate_rand_cont         /* SMP_GEN_SRAND_MRAND_CONT */
};


    #define SMP_PASSKEY_MASK    0xfff00000

    #if SMP_DEBUG == TRUE
static void smp_debug_print_nbyte_little_endian (UINT8 *p, const UINT8 *key_name, UINT8 len)
{
    int     i, x = 0;
    UINT8   p_buf[100];
    memset(p_buf, 0, 100);

    for (i = 0; i < len; i ++)
    {
        x += sprintf ((char *)&p_buf[x], "%02x ", p[i]);
    }
    SMP_TRACE_DEBUG("%s(LSB ~ MSB) = %s", key_name, p_buf);
}
    #else
        #define smp_debug_print_nbyte_little_endian(p, key_name, len)
    #endif

/*******************************************************************************
**
** Function         smp_encrypt_data
**
** Description      This function is called to generate passkey.
**
** Returns          void
**
*******************************************************************************/
BOOLEAN smp_encrypt_data (UINT8 *key, UINT8 key_len,
                          UINT8 *plain_text, UINT8 pt_len,
                          tSMP_ENC *p_out)
{
    aes_context     ctx;
    UINT8           *p_start = NULL;
    UINT8           *p = NULL;
    UINT8           *p_rev_data = NULL;    /* input data in big endilan format */
    UINT8           *p_rev_key = NULL;     /* input key in big endilan format */
    UINT8           *p_rev_output = NULL;  /* encrypted output in big endilan format */

    SMP_TRACE_DEBUG ("smp_encrypt_data");
    if ( (p_out == NULL ) || (key_len != SMP_ENCRYT_KEY_SIZE) )
    {
        BTM_TRACE_ERROR ("smp_encrypt_data Failed");
        return(FALSE);
    }

    if ((p_start = (UINT8 *)GKI_getbuf((SMP_ENCRYT_DATA_SIZE*4))) == NULL)
    {
        BTM_TRACE_ERROR ("smp_encrypt_data Failed unable to allocate buffer");
        return(FALSE);
    }

    if (pt_len > SMP_ENCRYT_DATA_SIZE)
        pt_len = SMP_ENCRYT_DATA_SIZE;

    memset(p_start, 0, SMP_ENCRYT_DATA_SIZE * 4);
    p = p_start;
    ARRAY_TO_STREAM (p, plain_text, pt_len); /* byte 0 to byte 15 */
    p_rev_data = p = p_start + SMP_ENCRYT_DATA_SIZE; /* start at byte 16 */
    REVERSE_ARRAY_TO_STREAM (p, p_start, SMP_ENCRYT_DATA_SIZE);  /* byte 16 to byte 31 */
    p_rev_key = p; /* start at byte 32 */
    REVERSE_ARRAY_TO_STREAM (p, key, SMP_ENCRYT_KEY_SIZE); /* byte 32 to byte 47 */

    smp_debug_print_nbyte_little_endian(key, (const UINT8 *)"Key", SMP_ENCRYT_KEY_SIZE);
    smp_debug_print_nbyte_little_endian(p_start, (const UINT8 *)"Plain text", SMP_ENCRYT_DATA_SIZE);
    p_rev_output = p;
    aes_set_key(p_rev_key, SMP_ENCRYT_KEY_SIZE, &ctx);
    aes_encrypt(p_rev_data, p, &ctx);  /* outputs in byte 48 to byte 63 */

    p = p_out->param_buf;
    REVERSE_ARRAY_TO_STREAM (p, p_rev_output, SMP_ENCRYT_DATA_SIZE);
    smp_debug_print_nbyte_little_endian(p_out->param_buf, (const UINT8 *)"Encrypted text", SMP_ENCRYT_KEY_SIZE);

    p_out->param_len = SMP_ENCRYT_KEY_SIZE;
    p_out->status = HCI_SUCCESS;
    p_out->opcode =  HCI_BLE_ENCRYPT;

    GKI_freebuf(p_start);

    return(TRUE);
}


/*******************************************************************************
**
** Function         smp_generate_passkey
**
** Description      This function is called to generate passkey.
**
** Returns          void
**
*******************************************************************************/
void smp_generate_passkey(tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    UNUSED(p_data);

    SMP_TRACE_DEBUG ("smp_generate_passkey");
    p_cb->rand_enc_proc = SMP_GEN_TK;

    /* generate MRand or SRand */
    if (!btsnd_hcic_ble_rand((void *)smp_rand_back))
        smp_rand_back(NULL);
}
/*******************************************************************************
**
** Function         smp_proc_passkey
**
** Description      This function is called to process a passkey.
**
** Returns          void
**
*******************************************************************************/
void smp_proc_passkey(tSMP_CB *p_cb , tBTM_RAND_ENC *p)
{
    UINT8   *tt = p_cb->tk;
    tSMP_KEY    key;
    UINT32  passkey; /* 19655 test number; */
    UINT8 *pp = p->param_buf;

    SMP_TRACE_DEBUG ("smp_proc_passkey ");
    STREAM_TO_UINT32(passkey, pp);
    passkey &= ~SMP_PASSKEY_MASK;

    /* truncate by maximum value */
    while (passkey > BTM_MAX_PASSKEY_VAL)
        passkey >>= 1;

    /* save the TK */
    memset(p_cb->tk, 0, BT_OCTET16_LEN);
    UINT32_TO_STREAM(tt, passkey);

    key.key_type = SMP_KEY_TYPE_TK;
    key.p_data  = p_cb->tk;

    if (p_cb->p_callback)
    {
        (*p_cb->p_callback)(SMP_PASSKEY_NOTIF_EVT, p_cb->pairing_bda, (tSMP_EVT_DATA *)&passkey);
    }

    smp_sm_event(p_cb, SMP_KEY_READY_EVT, (tSMP_INT_DATA *)&key);
}


/*******************************************************************************
**
** Function         smp_generate_stk
**
** Description      This function is called to generate STK calculated by running
**                  AES with the TK value as key and a concatenation of the random
**                  values.
**
** Returns          void
**
*******************************************************************************/
void smp_generate_stk (tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    BT_OCTET16      ptext;
    UINT8           *p = ptext;
    tSMP_ENC        output;
    tSMP_STATUS     status = SMP_PAIR_FAIL_UNKNOWN;
    UNUSED(p_data);

    SMP_TRACE_DEBUG ("smp_generate_stk ");

#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
    if(p_cb->is_secure)
    {
        /*simply compute the ltk*/
        smp_compute_sc_ltk(p_cb, p_data);
    }
    else
    {
#endif
    memset(p, 0, BT_OCTET16_LEN);
    if (p_cb->role == HCI_ROLE_MASTER)
    {
        memcpy(p, p_cb->rand, BT_OCTET8_LEN);
        memcpy(&p[BT_OCTET8_LEN], p_cb->rrand, BT_OCTET8_LEN);
    }
    else
    {
        memcpy(p, p_cb->rrand, BT_OCTET8_LEN);
        memcpy(&p[BT_OCTET8_LEN], p_cb->rand, BT_OCTET8_LEN);
    }

    /* generate STK = Etk(rand|rrand)*/
    if (!SMP_Encrypt( p_cb->tk, BT_OCTET16_LEN, ptext, BT_OCTET16_LEN, &output))
    {
        SMP_TRACE_ERROR("smp_generate_stk failed");
        smp_sm_event(p_cb, SMP_AUTH_CMPL_EVT, &status);
    }
    else
    {
        smp_process_stk(p_cb, &output);
    }
#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
    }
#endif

}
/*******************************************************************************
**
** Function         smp_generate_confirm
**
** Description      This function is called to start the second pairing phase by
**                  start generating initializer random number.
**
**
** Returns          void
**
*******************************************************************************/
void smp_generate_confirm (tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    UNUSED(p_data);

    SMP_TRACE_DEBUG ("smp_generate_confirm");
#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
    if(p_cb->is_secure)
    {
        smp_generate_nonce(p_cb, p_data);
        return;
    }
#endif
    p_cb->rand_enc_proc = SMP_GEN_SRAND_MRAND;
    /* generate MRand or SRand */
    if (!btsnd_hcic_ble_rand((void *)smp_rand_back))
        smp_rand_back(NULL);
}

#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)

/*******************************************************************************
**
** Function         smp_generate_nonce
**
** Description      This function is called to generate random number
**                  for LE SC.
**
** Returns          void
**
*******************************************************************************/
void smp_generate_nonce (tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    SMP_TRACE_DEBUG("%s", __FUNCTION__);
    p_cb->rand_enc_proc = SMP_GEN_SRAND_MRAND;
    /* generate MRand or SRand */
    if (!btsnd_hcic_ble_rand((void *)smp_rand_back))
        smp_rand_back(NULL);
}

/*******************************************************************************
**
** Function         smp_generate_oob_confirm
**
** Description      This function is called to generate OOB confirm and
**                  rand values for LE SC.
**
** Returns          void
**
*******************************************************************************/
void smp_generate_oob_confirm (tSMP_CB *p_cb)
{
    SMP_TRACE_DEBUG("%s", __FUNCTION__);
    UINT8 *p = NULL;
    BT_OCTET64 pk;
    UINT8 *p_start, *p_out;
    UINT8 z = 0x00;
    tSMP_KEY    key;

    UINT8 *loc_pubx = pk;// + 32;

    if((p = (UINT8 *)GKI_getbuf((SMP_ENCRYT_DATA_SIZE*6))) == NULL)
    {
        SMP_TRACE_ERROR("%s: error allocating buffer", __FUNCTION__);
        return;
    }
    memset(p, 0, SMP_ENCRYT_DATA_SIZE * 6);
    p_start = p;
    BTM_GetDevicePubKey ( pk );
    /*align the X cord of own public key */
    REVERSE_ARRAY_TO_STREAM(p, loc_pubx, SMP_ENCRYT_DATA_SIZE * 2);
    /*align the X cord of own public key */
    REVERSE_ARRAY_TO_STREAM(p, loc_pubx, SMP_ENCRYT_DATA_SIZE * 2);
    /*align the nonce*/
    REVERSE_ARRAY_TO_STREAM(p, p_cb->rand, SMP_ENCRYT_DATA_SIZE);

    aes_f4(p_start, p_start + SMP_ENCRYT_DATA_SIZE * 2,
           p_start + SMP_ENCRYT_DATA_SIZE * 4, &z, p_start + SMP_ENCRYT_DATA_SIZE * 5);
    p_out = p_start + (SMP_ENCRYT_DATA_SIZE * 5);
    REVERSE_STREAM_TO_ARRAY (p_cb->confirm, p_out, SMP_ENCRYT_DATA_SIZE);

    smp_debug_print_nbyte_little_endian(p_cb->confirm, (const UINT8 *)"------oob confirm value-----", 16);
    smp_debug_print_nbyte_little_endian(p_cb->rand, (const UINT8 *)"------oob rand value-----", 16);
    memcpy(p_cb->loob, p_cb->rand, SMP_ENCRYT_DATA_SIZE);
    GKI_freebuf(p_start);
}

/*******************************************************************************
**
** Function         smp_generate_sc_confirm
**
** Description      This function is called to generate confirm
**                  value for LE SC.
**
** Returns          void
**
*******************************************************************************/
void smp_generate_sc_confirm (tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    SMP_TRACE_DEBUG("%s", __FUNCTION__);
    UINT8 *p = NULL;
    BT_OCTET64 pk;
    UINT8 *p_start, *p_out, *p_tk;
    UINT8 z = 0x00;
    tSMP_KEY    key;
    UINT32      tk;

    p_tk = p_cb->tk;

    UINT8 *loc_pubx = pk;// + 32;
    UINT8 *rem_pubx = p_cb->rem_pub_key;// + 32;

    STREAM_TO_UINT32(tk, p_tk);/*passkey entry*/
    SMP_TRACE_DEBUG("%s, passkey entry is %d", __FUNCTION__, tk);
    //z |= ((tk >> (SMP_SEC_REPEAT_COUNT - p_cb->confirm_counter -1)) & 1);
    z |= ((tk >> (p_cb->confirm_counter)) & 1);
    if(p_cb->model == SMP_MODEL_PASSKEY || p_cb->model == SMP_MODEL_KEY_NOTIF)
        z |= 0x80;

    SMP_TRACE_DEBUG("%s, z is 0x%0x", __FUNCTION__, z);

    if((p = (UINT8 *)GKI_getbuf((SMP_ENCRYT_DATA_SIZE*6))) == NULL)
    {
        SMP_TRACE_ERROR("%s: error allocating buffer", __FUNCTION__);
        return;
    }
    memset(p, 0, SMP_ENCRYT_DATA_SIZE * 6);
    p_start = p;
    BTM_GetDevicePubKey ( pk );
    /*align the X cord of own public key */
    REVERSE_ARRAY_TO_STREAM(p, loc_pubx, SMP_ENCRYT_DATA_SIZE * 2);
    /*align the X cord of remote public key */
    REVERSE_ARRAY_TO_STREAM(p, rem_pubx, SMP_ENCRYT_DATA_SIZE * 2);
    /*align the nonce*/
    REVERSE_ARRAY_TO_STREAM(p, p_cb->rand, SMP_ENCRYT_DATA_SIZE);

    aes_f4(p_start, p_start + SMP_ENCRYT_DATA_SIZE * 2,
           p_start + SMP_ENCRYT_DATA_SIZE * 4, &z, p_start + SMP_ENCRYT_DATA_SIZE * 5);
    p_out = p_start + (SMP_ENCRYT_DATA_SIZE * 5);
    REVERSE_STREAM_TO_ARRAY (p_cb->confirm, p_out, SMP_ENCRYT_DATA_SIZE);

    /*this below check might not be needed at all . EVALUATE*/
    if(p_cb->role == HCI_ROLE_SLAVE ||
       (p_cb->model == SMP_MODEL_PASSKEY || p_cb->model == SMP_MODEL_KEY_NOTIF))
    {
        key.key_type = SMP_KEY_TYPE_SC_CFM;
        key.p_data = p_cb->confirm;
        smp_sm_event(p_cb, SMP_KEY_READY_EVT, &key);
    }

    GKI_freebuf(p_start);
}


/*******************************************************************************
**
** Function         smp_verify_oob_confirm
**
** Description      This function is called to verify the value of OOB
**                  confirm for LE SC.
**
** Returns          BOOLEAN
**
*******************************************************************************/
BOOLEAN smp_verify_oob_confirm (tSMP_CB *p_cb)
{
    SMP_TRACE_DEBUG("%s", __FUNCTION__);
    UINT8 *p = NULL;
    UINT8 *p_start, *p_out;
    UINT8 z = 0x00;
    UINT8   result;

    result = FALSE;
    BT_OCTET16 rem_confirm; /*calculated value by local host*/

    UINT8 *rem_pubx = p_cb->rem_pub_key;// + 32;

    if((p = (UINT8 *)GKI_getbuf((SMP_ENCRYT_DATA_SIZE*6))) == NULL)
    {
        SMP_TRACE_ERROR("%s: error allocating buffer", __FUNCTION__);
        return result;
    }
    memset(p, 0, SMP_ENCRYT_DATA_SIZE * 6);
    p_start = p;
    /*align the X cord of rem public key */
    REVERSE_ARRAY_TO_STREAM(p, rem_pubx, SMP_ENCRYT_DATA_SIZE * 2);
    /*align the X cord of remote public key */
    REVERSE_ARRAY_TO_STREAM(p, rem_pubx, SMP_ENCRYT_DATA_SIZE * 2);
    /*align the remote nonce*/
    REVERSE_ARRAY_TO_STREAM(p, p_cb->rrand, SMP_ENCRYT_DATA_SIZE);

    aes_f4(p_start, p_start + SMP_ENCRYT_DATA_SIZE * 2,
           p_start + SMP_ENCRYT_DATA_SIZE * 4, &z, p_start + SMP_ENCRYT_DATA_SIZE * 5);
    p_out = p_start + (SMP_ENCRYT_DATA_SIZE * 5);
    REVERSE_STREAM_TO_ARRAY (rem_confirm, p_out, SMP_ENCRYT_DATA_SIZE);

    if(!memcmp(rem_confirm, p_cb->rconfirm, BT_OCTET16_LEN))
    {
        SMP_TRACE_DEBUG("%s: oob confirm value matches", __FUNCTION__);
        result =  TRUE;
    }
    else
    {
        SMP_TRACE_DEBUG("%s: oob confirm value failed to match", __FUNCTION__);
        result = FALSE;
    }
    GKI_freebuf(p_start);
    return result;
}



/*******************************************************************************
**
** Function         smp_verify_sc_confirm
**
** Description      This function is called to verify the confirm
**                  for LE SC.
**
** Returns          void
**
*******************************************************************************/
void smp_verify_sc_confirm (tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    SMP_TRACE_DEBUG("%s", __FUNCTION__);
    UINT8 *p = NULL;
    BT_OCTET64 pk;
    UINT8 *p_start, *p_out, *p_tk;
    UINT8 z = 0x00;
    UINT8   reason;
    BT_OCTET16 rem_confirm; /*calculated value by local host*/
    UINT32 tk;
    p_tk = p_cb->tk;

    STREAM_TO_UINT32(tk, p_tk);/*passkey entry*/
    SMP_TRACE_DEBUG("%s, passkey entry is %d", __FUNCTION__, tk);
    //z |= ((tk >> (SMP_SEC_REPEAT_COUNT - p_cb->confirm_counter -1)) & 1);
    z |= ((tk >> (p_cb->confirm_counter)) & 1);
    if(p_cb->model == SMP_MODEL_PASSKEY || p_cb->model == SMP_MODEL_KEY_NOTIF)
        z |= 0x80;

    UINT8 *loc_pubx = pk;// + 32;
    UINT8 *rem_pubx = p_cb->rem_pub_key;// + 32;

    if((p = (UINT8 *)GKI_getbuf((SMP_ENCRYT_DATA_SIZE*6))) == NULL)
    {
        SMP_TRACE_ERROR("%s: error allocating buffer", __FUNCTION__);
        return;
    }
    memset(p, 0, SMP_ENCRYT_DATA_SIZE * 6);
    p_start = p;
    BTM_GetDevicePubKey ( pk );
    /*align the X cord of rem public key */
    REVERSE_ARRAY_TO_STREAM(p, rem_pubx, SMP_ENCRYT_DATA_SIZE * 2);
    /*align the X cord of remote public key */
    REVERSE_ARRAY_TO_STREAM(p, loc_pubx, SMP_ENCRYT_DATA_SIZE * 2);
    /*align the remote nonce*/
    REVERSE_ARRAY_TO_STREAM(p, p_cb->rrand, SMP_ENCRYT_DATA_SIZE);

    aes_f4(p_start, p_start + SMP_ENCRYT_DATA_SIZE * 2,
           p_start + SMP_ENCRYT_DATA_SIZE * 4, &z, p_start + SMP_ENCRYT_DATA_SIZE * 5);
    p_out = p_start + (SMP_ENCRYT_DATA_SIZE * 5);
    REVERSE_STREAM_TO_ARRAY (rem_confirm, p_out, SMP_ENCRYT_DATA_SIZE);

    if(!memcmp(rem_confirm, p_cb->rconfirm, BT_OCTET16_LEN) &&
       ( p_cb->model == SMP_MODEL_ENC_ONLY || p_cb->model == SMP_MODEL_NUM_COMP))
    {
        SMP_TRACE_DEBUG("%s, confirm value matches", __FUNCTION__);
        if(p_cb->role == HCI_ROLE_MASTER && p_cb->dhk_recvd)
        {
            smp_sm_event(p_cb, SMP_DH_KEY_EVT, NULL);
        }
        else if (p_cb->role == HCI_ROLE_MASTER && !p_cb->dhk_recvd)
        {
            SMP_TRACE_DEBUG("%s, DHKey has not been recvd yet", __FUNCTION__);
            p_cb->cb_evt = SMP_DHKEY_REQ_EVT;
        }
    }
    else if(!memcmp(rem_confirm, p_cb->rconfirm, BT_OCTET16_LEN) &&
            (p_cb->model == SMP_MODEL_KEY_NOTIF || p_cb->model == SMP_MODEL_PASSKEY))
    {
        SMP_TRACE_DEBUG("%s, confirm value matches and model is entry input, counter=%d", __FUNCTION__, p_cb->confirm_counter);
        if(p_cb->confirm_counter < SMP_SEC_REPEAT_COUNT - 1)
        {
            /*repeat the process*/
             p_cb->flags &= ~SMP_PAIR_FLAGS_CMD_CONFIRM;
             p_cb->confirm_counter ++;
             SMP_TRACE_DEBUG("%s, confirm value matches, sending repeat evt, counter=%d",__FUNCTION__, p_cb->confirm_counter);
             smp_sm_event(p_cb, SMP_CONFIRM_REPEAT_EVT, NULL);
        }
        else
        {
            if(p_cb->dhk_recvd)
            {
                smp_sm_event(p_cb, SMP_DH_KEY_EVT, NULL);
            }
            else
            {
                SMP_TRACE_DEBUG("%s, DHKey has not been recvd yet", __FUNCTION__);
                p_cb->cb_evt = SMP_DHKEY_REQ_EVT;
            }
        }
    }
    else if(p_cb->model == SMP_MODEL_OOB)
    {
        if(p_cb->dhk_recvd)
        {
            smp_sm_event(p_cb, SMP_DH_KEY_EVT, NULL);
        }
        else
        {
            SMP_TRACE_DEBUG("%s, DHKey has not been recvd yet", __FUNCTION__);
            p_cb->cb_evt = SMP_DHKEY_REQ_EVT;
        }
    }
    else
    {
        reason = p_cb->failure = SMP_CONFIRM_VALUE_ERR;
        smp_sm_event(p_cb, SMP_AUTH_CMPL_EVT, &reason);
    }

    GKI_freebuf(p_start);
}

/*******************************************************************************
**
** Function         smp_generate_verifier
**
** Description      This function is called to generate verifier passkey
**                  for LE SC numeric comparison.
**
** Returns          void
**
*******************************************************************************/
void smp_generate_verifier (tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    SMP_TRACE_DEBUG("%s", __FUNCTION__);
    UINT8 *p = NULL;
    BT_OCTET64 pk;
    UINT8 *p_start;
    UINT8   reason;

    UINT8 *loc_pubx = pk;// + 32;
    UINT8 *rem_pubx = p_cb->rem_pub_key;// + 32;
    UINT8 p_out[4]; /*save the output of g2*/
    UINT32 verifier;

    if((p = (UINT8 *)GKI_getbuf((SMP_ENCRYT_DATA_SIZE*6))) == NULL)
    {
        SMP_TRACE_ERROR("%s: error allocating buffer", __FUNCTION__);
        return;
    }
    memset(p, 0, SMP_ENCRYT_DATA_SIZE * 6);
    p_start = p;
    BTM_GetDevicePubKey ( pk );

    /*g2(pub_init(32), pub_resp(32), rand_init(32), rand_resp(32))*/
    /*align the X cord of rem public key */
    REVERSE_ARRAY_TO_STREAM(p, loc_pubx, SMP_ENCRYT_DATA_SIZE * 2);

    /*align the X cord of local public key */
    REVERSE_ARRAY_TO_STREAM(p, rem_pubx, SMP_ENCRYT_DATA_SIZE * 2);

    /*align the local nonce*/
    REVERSE_ARRAY_TO_STREAM(p, p_cb->rand, SMP_ENCRYT_DATA_SIZE);

    /*align the remote nonce*/
    REVERSE_ARRAY_TO_STREAM(p, p_cb->rrand, SMP_ENCRYT_DATA_SIZE);

    if(p_cb->role == HCI_ROLE_MASTER)
    {
        aes_g2(p_start, p_start + SMP_ENCRYT_DATA_SIZE*2,
               p_start + SMP_ENCRYT_DATA_SIZE*4, p_start + SMP_ENCRYT_DATA_SIZE*5,
               p_out);
    }
    else
    {
        aes_g2(p_start + SMP_ENCRYT_DATA_SIZE*2, p_start,
               p_start + SMP_ENCRYT_DATA_SIZE*5, p_start + SMP_ENCRYT_DATA_SIZE*4,
               p_out);
    }
    smp_debug_print_nbyte_little_endian(p_out, (const UINT8 *)"------remote commit_value-----", 4);
    verifier = (((UINT32)(*p_out) << 24) + ((UINT32)(*(p_out + 1)) << 16) +
                ((UINT32)(*(p_out + 2)) << 8) + ((UINT32)(*(p_out + 3))));
    SMP_TRACE_DEBUG("%s: verifier before trunc = %d", __FUNCTION__, verifier);
    verifier = verifier % (1000000);
    SMP_TRACE_DEBUG("%s: verifier = %d", __FUNCTION__, verifier);

    /*send verifier to APIs for confirm*/
    p_cb->cb_evt = SMP_PASSKEY_CONFIRM_EVT;
    SMP_TRACE_DEBUG("%s: model=%d", __FUNCTION__, p_cb->model);
    if (p_cb->p_callback && p_cb->model == SMP_MODEL_NUM_COMP)
    {
        (*p_cb->p_callback)(SMP_PASSKEY_CONFIRM_EVT, p_cb->pairing_bda, (tSMP_EVT_DATA *)&verifier);
    }
    else /*if(p_cb->model == SMP_MODEL_ENC_ONLY)*/
    {
        SMP_SecurityGrant(p_cb->pairing_bda, SMP_SUCCESS);
    }
    GKI_freebuf(p_start);
}

/*******************************************************************************
**
** Function         smp_generate_mackey
**
** Description      This function is called to generate mackey
**                  and LTK for LE SC.
**
** Returns          void
**
*******************************************************************************/
void smp_generate_mackey(tSMP_CB *p_cb, tSMP_INT_DATA *p_data, UINT8 counter)
{
    SMP_TRACE_DEBUG("%s, counter=%d", __FUNCTION__, counter);
    /*f5(counter=0, dhkey, n1, n2, a1, a2, length=256)*/
    BD_ADDR remote_bda;
    UINT8 *p_out, *p;
    UINT8 *p_start;
    tBLE_ADDR_TYPE addr_type = 0;
    UINT8 p_keyID[] = {0x62, 0x74, 0x6c, 0x65};/*btle*/
    if (!BTM_ReadRemoteConnectionAddr(p_cb->pairing_bda, remote_bda, &addr_type))
    {
        SMP_TRACE_ERROR("%s: can not generate macKey for unknown device", __FUNCTION__);
        return;
    }
    //p_cb->local_bda, p_cb->addr_type
    if((p = (UINT8 *)GKI_getbuf((SMP_ENCRYT_DATA_SIZE*6))) == NULL)
    {
        SMP_TRACE_ERROR("%s: error allocating buffer", __FUNCTION__);
        return;
    }
    memset(p, 0, SMP_ENCRYT_DATA_SIZE * 6);
    p_start = p;
    REVERSE_ARRAY_TO_STREAM(p, p_cb->dhkey, SMP_ENCRYT_DATA_SIZE * 2);/*dhkey*/
    REVERSE_ARRAY_TO_STREAM(p, p_cb->rand, SMP_ENCRYT_DATA_SIZE);/*rand*/
    REVERSE_ARRAY_TO_STREAM(p, p_cb->rrand, SMP_ENCRYT_DATA_SIZE);/*rrand*/
    *(p)++ = p_cb->addr_type;/*loc addr type*/
    BDADDR_TO_STREAM_BIGEND(p, p_cb->local_bda);/*loc addr*/
    *(p)++ = addr_type;/*rem addr type*/
    BDADDR_TO_STREAM_BIGEND(p, remote_bda);/*rem addr*/

    if(p_cb->role == HCI_ROLE_MASTER)
    {
        aes_f5_v2(counter, p_start, p_start + SMP_ENCRYT_DATA_SIZE*2,
                  p_start + SMP_ENCRYT_DATA_SIZE*3, p_keyID, p_start + SMP_ENCRYT_DATA_SIZE*4,
                  p_start + (SMP_ENCRYT_DATA_SIZE*4 + 7), p_start + SMP_ENCRYT_DATA_SIZE*5);
    }
    else
    {
        aes_f5_v2(counter, p_start, p_start + SMP_ENCRYT_DATA_SIZE*3,
                  p_start + SMP_ENCRYT_DATA_SIZE*2, p_keyID, p_start + (SMP_ENCRYT_DATA_SIZE*4 + 7),
                  p_start + SMP_ENCRYT_DATA_SIZE*4, p_start + SMP_ENCRYT_DATA_SIZE*5);
    }
    p_out = p_start + SMP_ENCRYT_DATA_SIZE*5;

    smp_debug_print_nbyte_little_endian(p_out, (const UINT8 *)"------MAC KEY/ LTK------", 16);

    /*save mackey/ltk in little endian format*/
    if(counter == 0)
    {
        REVERSE_STREAM_TO_ARRAY (p_cb->mackey, p_out, SMP_ENCRYT_DATA_SIZE);
    }
    else if(counter == 1)
    {
        REVERSE_STREAM_TO_ARRAY (p_cb->ltk, p_out, SMP_ENCRYT_DATA_SIZE);
    }

    p_cb->flags |= SMP_PAIR_FLAGS_MACKEY_COMP;

    GKI_freebuf(p_start);
}

/*******************************************************************************
**
** Function         smp_compute_commit
**
** Description      This function is called to generate DHKEY check
**                  for LE SC.
**
** Returns          void
**
*******************************************************************************/
void smp_compute_commit (tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    SMP_TRACE_DEBUG("%s", __FUNCTION__);
    UINT8 *p = NULL;
    UINT8 *p_start, *p_out, *p_tk, *p_roob;
    UINT8   reason;
    UINT8 zero_block[SMP_ENCRYT_DATA_SIZE] = {0};
    UINT8 iocap[3];
    tBLE_ADDR_TYPE addr_type = 0;
    tSMP_KEY    key;
    BD_ADDR remote_bda;
    p_tk = p_cb->tk;

    if(p_cb->model == SMP_MODEL_PASSKEY || p_cb->model == SMP_MODEL_KEY_NOTIF)
    {
        REVERSE_STREAM_TO_ARRAY(zero_block, p_tk, SMP_ENCRYT_DATA_SIZE);
        //memcpy(zero_block, p_tk, SMP_ENCRYT_DATA_SIZE);
    }
    else if(p_cb->model == SMP_MODEL_OOB)
    {
        p_roob = p_cb->roob;
        REVERSE_STREAM_TO_ARRAY(zero_block, p_roob, SMP_ENCRYT_DATA_SIZE);
    }

    if (!BTM_ReadRemoteConnectionAddr(p_cb->pairing_bda, remote_bda, &addr_type))
    {
        SMP_TRACE_ERROR("%s: can not generate commit for unknown device", __FUNCTION__);
        return;
    }

    BTM_ReadConnectionAddr( p_cb->pairing_bda, p_cb->local_bda, &p_cb->addr_type);

    UINT8 res= *(UINT8 *)p_data;
    if (res != SMP_SUCCESS)
    {
        p_cb->cb_evt=0;
        reason = p_cb->failure = SMP_NUM_COMP_FAIL;
        SMP_TRACE_DEBUG("%s: confirm evt not YES", __FUNCTION__);
        smp_sm_event(p_cb, SMP_AUTH_CMPL_EVT, &reason);
        return;
    }
    /*generate the mackey first*/
    if(p_cb->flags & SMP_PAIR_FLAGS_MACKEY_COMP) /*mackey already computed*/
    {
        SMP_TRACE_DEBUG("%s: MacKey already computed", __FUNCTION__);
    }
    else
    {
        smp_generate_mackey(p_cb, p_data, 0);
    }

    if((p = (UINT8 *)GKI_getbuf((SMP_ENCRYT_DATA_SIZE*5))) == NULL)
    {
        SMP_TRACE_ERROR("%s: error allocating buffer", __FUNCTION__);
        return;
    }
    memset(p, 0, SMP_ENCRYT_DATA_SIZE * 5);
    p_start = p;
    REVERSE_ARRAY_TO_STREAM(p, p_cb->mackey, SMP_ENCRYT_DATA_SIZE);/*mackey*/
    REVERSE_ARRAY_TO_STREAM(p, p_cb->rand, SMP_ENCRYT_DATA_SIZE);/*rand*/
    REVERSE_ARRAY_TO_STREAM(p, p_cb->rrand, SMP_ENCRYT_DATA_SIZE);/*rrand*/
    *p = p_cb->addr_type;/*loc addr type*/
    p++;
    BDADDR_TO_STREAM_BIGEND(p, p_cb->local_bda);/*loc addr*/
    *p = addr_type;/*rem addr type*/
    p++;
    BDADDR_TO_STREAM_BIGEND(p, remote_bda);/*rem addr*/

    iocap[0] = p_cb->loc_auth_req;
    iocap[1] = p_cb->loc_oob_flag;
    iocap[2] = p_cb->loc_io_caps;

    aes_f6(p_start, p_start + SMP_ENCRYT_DATA_SIZE,
           p_start + SMP_ENCRYT_DATA_SIZE*2, zero_block, iocap,
           p_start + SMP_ENCRYT_DATA_SIZE*3, p_start + (SMP_ENCRYT_DATA_SIZE*3 + 7),
           p_start + SMP_ENCRYT_DATA_SIZE*4);
    p_out = p_start + SMP_ENCRYT_DATA_SIZE*4;
    smp_debug_print_nbyte_little_endian(p_start, (const UINT8 *)"----mackey-------", 16);
    smp_debug_print_nbyte_little_endian(p_start + SMP_ENCRYT_DATA_SIZE, (const UINT8 *)"----rand-------", 16);
    smp_debug_print_nbyte_little_endian(p_start + SMP_ENCRYT_DATA_SIZE*2, (const UINT8 *)"----rrand-------", 16);
    smp_debug_print_nbyte_little_endian(p_start + SMP_ENCRYT_DATA_SIZE*3, (const UINT8 *)"----localbda-------", 7);
    smp_debug_print_nbyte_little_endian(p_start + (SMP_ENCRYT_DATA_SIZE*3 + 7), (const UINT8 *)"----rembda-------", 7);
    smp_debug_print_nbyte_little_endian(iocap, (const UINT8 *)"----loc iocap-------", 3);
    smp_debug_print_nbyte_little_endian(zero_block, (const UINT8 *)"------zero_block-----", 16);
    smp_debug_print_nbyte_little_endian(p_out, (const UINT8 *)"------commit_value-----", 16);

    /*save mackey in little endian format*/
    REVERSE_STREAM_TO_ARRAY (p_cb->commit, p_out, SMP_ENCRYT_DATA_SIZE);

    /*if slave and commit already verified, send the commit*/
    if(p_cb->role == HCI_ROLE_SLAVE && p_cb->flags & SMP_PAIR_FLAGS_CMD_COMMIT)
    {
        key.key_type = SMP_KEY_TYPE_COMMIT;
        key.p_data = p_cb->commit;
        smp_sm_event(p_cb, SMP_KEY_READY_EVT, &key);
    }

    GKI_freebuf(p_start);
}


/*******************************************************************************
**
** Function         smp_process_commit
**
** Description      This function is called to verify DHKEY check
**                  from remote for LE SC.
**
** Returns          void
**
*******************************************************************************/
void smp_process_commit (tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    SMP_TRACE_DEBUG("%s", __FUNCTION__);
    UINT8 *p = NULL;
    UINT8 *p_start, *p_out, *p_tk, *p_loob;
    UINT8   reason;
    UINT8 zero_block[SMP_ENCRYT_DATA_SIZE] = {0};
    UINT8 iocap[3];
    tBLE_ADDR_TYPE addr_type = 0;
    BD_ADDR remote_bda;
    UINT8 *p_key = (UINT8 *)p_data;
    BT_OCTET16 rcommit_loc; /*locally calculated remote commit val*/
    tSMP_KEY    key;

    p_tk = p_cb->tk;

    if(p_cb->model == SMP_MODEL_PASSKEY || p_cb->model == SMP_MODEL_KEY_NOTIF)
    {
        REVERSE_STREAM_TO_ARRAY(zero_block, p_tk, SMP_ENCRYT_DATA_SIZE);
        //memcpy(zero_block, p_tk, SMP_ENCRYT_DATA_SIZE);
    }
    else if (p_cb->model == SMP_MODEL_OOB && p_cb->peer_oob_flag)
    {
        p_loob = p_cb->loob;
        REVERSE_STREAM_TO_ARRAY(zero_block, p_loob, SMP_ENCRYT_DATA_SIZE);
    }

    /*save the remote commit first*/
    if(p_key != NULL)
    {
        STREAM_TO_ARRAY(p_cb->rcommit, p_key, BT_OCTET16_LEN);
    }
    p_cb->flags |= SMP_PAIR_FLAGS_CMD_COMMIT;/* remote commit received*/

    /*now calculate the remote commit based on own params*/

    if (!BTM_ReadRemoteConnectionAddr(p_cb->pairing_bda, remote_bda, &addr_type))
    {
        SMP_TRACE_ERROR("%s: can not generate commit for unknown device", __FUNCTION__);
        return;
    }

    BTM_ReadConnectionAddr( p_cb->pairing_bda, p_cb->local_bda, &p_cb->addr_type);

    /*generate the mackey first*/
    if(p_cb->flags & SMP_PAIR_FLAGS_MACKEY_COMP) /*mackey already computed*/
    {
        SMP_TRACE_DEBUG("%s: MacKey already computed", __FUNCTION__);
    }
    else
    {
        smp_generate_mackey(p_cb, p_data, 0);
    }

    if((p = (UINT8 *)GKI_getbuf((SMP_ENCRYT_DATA_SIZE*5))) == NULL)
    {
        SMP_TRACE_ERROR("%s: error allocating buffer", __FUNCTION__);
        return;
    }
    memset(p, 0, SMP_ENCRYT_DATA_SIZE * 5);
    p_start = p;
    REVERSE_ARRAY_TO_STREAM(p, p_cb->mackey, SMP_ENCRYT_DATA_SIZE);/*mackey*/
    REVERSE_ARRAY_TO_STREAM(p, p_cb->rand, SMP_ENCRYT_DATA_SIZE);/*rand*/
    REVERSE_ARRAY_TO_STREAM(p, p_cb->rrand, SMP_ENCRYT_DATA_SIZE);/*rrand*/
    *p = p_cb->addr_type;/*loc addr type*/
    p++;
    BDADDR_TO_STREAM_BIGEND(p, p_cb->local_bda);/*loc addr*/
    *p = addr_type;/*rem addr type*/
    p++;
    BDADDR_TO_STREAM_BIGEND(p, remote_bda);/*rem addr*/

    iocap[0] = p_cb->peer_auth_req;
    iocap[1] = p_cb->peer_oob_flag;
    iocap[2] = p_cb->peer_io_caps;

    aes_f6(p_start, p_start + SMP_ENCRYT_DATA_SIZE*2,
           p_start + SMP_ENCRYT_DATA_SIZE, zero_block, iocap,
           p_start + (SMP_ENCRYT_DATA_SIZE*3 + 7), p_start + SMP_ENCRYT_DATA_SIZE*3,
           p_start + SMP_ENCRYT_DATA_SIZE*4);
    p_out = p_start + SMP_ENCRYT_DATA_SIZE*4;
    smp_debug_print_nbyte_little_endian(p_start, (const UINT8 *)"----mackey-------", 16);
    smp_debug_print_nbyte_little_endian(p_start + SMP_ENCRYT_DATA_SIZE, (const UINT8 *)"----rand-------", 16);
    smp_debug_print_nbyte_little_endian(p_start + SMP_ENCRYT_DATA_SIZE*2, (const UINT8 *)"----rrand-------", 16);
    smp_debug_print_nbyte_little_endian(p_start + SMP_ENCRYT_DATA_SIZE*3, (const UINT8 *)"----localbda-------", 7);
    smp_debug_print_nbyte_little_endian(p_start + (SMP_ENCRYT_DATA_SIZE*3 + 7), (const UINT8 *)"----rembda-------", 7);
    smp_debug_print_nbyte_little_endian(iocap, (const UINT8 *)"----rem iocap-------", 3);
    smp_debug_print_nbyte_little_endian(zero_block, (const UINT8 *)"------zero_block-----", 16);

    smp_debug_print_nbyte_little_endian(p_out, (const UINT8 *)"------remote commit_value-----", 16);

    /*save remote commit in little endian format*/
    REVERSE_STREAM_TO_ARRAY (rcommit_loc, p_out, SMP_ENCRYT_DATA_SIZE);

    /*compare the remote commit value for verification*/
    if(!memcmp(p_cb->rcommit, rcommit_loc, BT_OCTET16_LEN))
    {
        SMP_TRACE_DEBUG("%s: commit value verified", __FUNCTION__);
        if(p_cb->role == HCI_ROLE_SLAVE && p_cb->state == SMP_ST_COMMIT)
        {
            key.key_type = SMP_KEY_TYPE_COMMIT;
            key.p_data = p_cb->commit;
            smp_sm_event(p_cb, SMP_KEY_READY_EVT, &key);
        }
        if(p_cb->role == HCI_ROLE_MASTER)
        {
            /*make sure the key dist is in sync with slave*/
            p_cb->loc_i_key = p_cb->peer_i_key;
            p_cb->loc_r_key = p_cb->peer_r_key;
            smp_sm_event(p_cb, SMP_ENC_REQ_EVT, NULL);/*request LTK generation*/
        }
    }
    else
    {
        SMP_TRACE_ERROR("%s: commit value doesnt match", __FUNCTION__);
        reason = p_cb->failure = SMP_DHKEY_CHECK_FAIL;
        p_cb->flags &= ~SMP_PAIR_FLAGS_CMD_COMMIT;
        smp_sm_event(p_cb, SMP_AUTH_CMPL_EVT, &reason);
    }

    GKI_freebuf(p_start);
}

/*******************************************************************************
**
** Function         smp_derive_LTK
**
** Description      This function is called to derive LTK from linkkey
**                  for LE SC.
**
** Returns          void
**
*******************************************************************************/
void smp_derive_LTK(tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    SMP_TRACE_DEBUG("%s", __FUNCTION__);
    UINT8 reason;
    UINT8 *p = NULL;
    tBTM_SEC_DEV_REC *p_dev_rec = btm_find_dev(p_cb->pairing_bda);
    if(p_dev_rec == NULL ||  !(p_dev_rec->sec_flags &  BTM_SEC_LINK_KEY_KNOWN))
    {
        reason = p_cb->failure = SMP_FAIL;
        SMP_TRACE_ERROR("%s: link key not found", __FUNCTION__);
        smp_sm_event(p_cb, SMP_AUTH_CMPL_EVT, &reason);
        return;
    }
    else
    {
        memcpy(p_cb->link_key, p_dev_rec->link_key, LINK_KEY_LEN);
    }

    UINT8 tmp[] = {0x74, 0x6D, 0x70, 0x32};
    UINT8 lebr[] = {0x62, 0x72, 0x6C, 0x65};
    UINT8 *p_iltk;
    UINT8 *p_linkkey, *p_start;

    tBTM_LE_PENC_KEYS   le_key_peer;
    tBTM_LE_LENC_KEYS   le_key_loc;

    if((p = (UINT8 *)GKI_getbuf((SMP_ENCRYT_DATA_SIZE*3))) == NULL)
    {
        SMP_TRACE_ERROR("%s: error allocating buffer", __FUNCTION__);
        return;
    }
    memset(p, 0, SMP_ENCRYT_DATA_SIZE * 3);
    p_start = p;
    ARRAY_TO_STREAM(p, p_cb->link_key, SMP_ENCRYT_DATA_SIZE);/*linkkey need not be reversed*/
    aes_cmac(tmp, p_start, 4, p+SMP_ENCRYT_DATA_SIZE);
    p_iltk = p+SMP_ENCRYT_DATA_SIZE;

    /*generate the ltk now*/
    aes_cmac(lebr, p_iltk, 4, p+(2*SMP_ENCRYT_DATA_SIZE));
    p_linkkey = p + (2*SMP_ENCRYT_DATA_SIZE);/*derived LTK*/

    smp_debug_print_nbyte_little_endian(p_linkkey, (const UINT8 *)"------LTK derived-----", 16);
    /*save linkkey in little endian format*/
    REVERSE_STREAM_TO_ARRAY (p_cb->ltk, p_linkkey, SMP_ENCRYT_DATA_SIZE);

    /*set the sec_level*/
    if(p_cb->is_secure)
    {
        p_cb->sec_level |= SMP_SEC_LE_SECURE;
    }
    if(p_dev_rec->link_key_type == HCI_LKEY_TYPE_AUTH_COMB_P256 || p_dev_rec->link_key_type == HCI_LKEY_TYPE_AUTH_COMB)
    {
        p_cb->sec_level |= SMP_SEC_AUTHENTICATED;
    }
    else
    {
        p_cb->sec_level |= SMP_SEC_UNAUTHENTICATE;
    }
    BTM_TRACE_DEBUG("%s sec_level = 0x%x", __FUNCTION__, p_cb->sec_level);

    /*save the peer key*/
    le_key_peer.key_size  = p_cb->loc_enc_size;
    le_key_peer.sec_level = p_cb->sec_level;
    le_key_peer.ediv = 0;
    memset(le_key_peer.rand, 0, BT_OCTET8_LEN );
    memcpy(le_key_peer.ltk, p_cb->ltk, BT_OCTET16_LEN);
    btm_sec_save_le_key(p_cb->pairing_bda, BTM_LE_KEY_PENC, (tBTM_LE_KEY_VALUE *)&le_key_peer, TRUE);

    /*save the local key (same as penc)*/
    le_key_loc.div =  p_cb->div;
    le_key_loc.key_size = p_cb->loc_enc_size;
    le_key_loc.sec_level = p_cb->sec_level;
    btm_sec_save_le_key(p_cb->pairing_bda, BTM_LE_KEY_LENC, (tBTM_LE_KEY_VALUE *)&le_key_loc, TRUE);

    /*LTK and link key is assumed exchanged here*/
    p_cb->loc_i_key &= ~SMP_SEC_KEY_TYPE_LINK;
    p_cb->loc_r_key &= ~SMP_SEC_KEY_TYPE_LINK;

    /*adjust the key distr map accordingly*/
    p_cb->loc_i_key &= ~SMP_SEC_KEY_TYPE_ENC;
    p_cb->loc_r_key &= ~SMP_SEC_KEY_TYPE_ENC;
    GKI_freebuf(p_start);
}

/*******************************************************************************
**
** Function         smp_derive_link_key
**
** Description      This function is called to derive linkkey from LTK
**                  for LE SC.
**
** Returns          void
**
*******************************************************************************/
static void smp_derive_link_key(tSMP_CB *p_cb)
{
    SMP_TRACE_DEBUG("%s", __FUNCTION__);
    UINT8 *p = NULL;
    UINT8 tmp[] = {0x74, 0x6D, 0x70, 0x31};
    UINT8 lebr[] = {0x6C, 0x65, 0x62, 0x72};
    UINT8 *p_iltk;
    UINT8 *p_linkkey, *p_start;
    if((p = (UINT8 *)GKI_getbuf((SMP_ENCRYT_DATA_SIZE*3))) == NULL)
    {
        SMP_TRACE_ERROR("%s: error allocating buffer", __FUNCTION__);
        return;
    }
    memset(p, 0, SMP_ENCRYT_DATA_SIZE * 3);
    p_start = p;
    REVERSE_ARRAY_TO_STREAM(p, p_cb->ltk, SMP_ENCRYT_DATA_SIZE);/*ltk*/
    aes_cmac(tmp, p_start, 4, p+SMP_ENCRYT_DATA_SIZE);
    p_iltk = p+SMP_ENCRYT_DATA_SIZE;

    /*generate the link now*/
    aes_cmac(lebr, p_iltk, 4, p+(2*SMP_ENCRYT_DATA_SIZE));
    p_linkkey = p + (2*SMP_ENCRYT_DATA_SIZE);

    smp_debug_print_nbyte_little_endian(p_linkkey, (const UINT8 *)"------Br-EDR linkkey-----", 16);
    /*save linkkey in little endian format*/
    //REVERSE_STREAM_TO_ARRAY (p_cb->link_key, p_linkkey, SMP_ENCRYT_DATA_SIZE);
    /*do not save linkkey in little endian format as link key is reversed again by BREDR enc*/
    memcpy(p_cb->link_key, p_linkkey, SMP_ENCRYT_DATA_SIZE);
    GKI_freebuf(p_start);
}

/*******************************************************************************
**
** Function         smp_compute_sc_ltk
**
** Description      This function is called to generate LTK and derive
**                  linkkey for LE SC.
**
** Returns          void
**
*******************************************************************************/
void smp_compute_sc_ltk (tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    SMP_TRACE_DEBUG("%s", __FUNCTION__);
    tSMP_KEY    key;
    tBTM_LE_LENC_KEYS   le_key_loc;
    tBTM_LE_PENC_KEYS   le_key_peer;
    smp_generate_mackey(p_cb, p_data, 1);
    if((p_cb->loc_i_key & SMP_SEC_KEY_TYPE_LINK) && (p_cb->loc_r_key & SMP_SEC_KEY_TYPE_LINK))
    {
        SMP_TRACE_DEBUG("%s, Also generate the BR/EDR link key here", __FUNCTION__);
        smp_derive_link_key(p_cb);
    }
    p_cb->loc_i_key &= ~SMP_SEC_KEY_TYPE_LINK;
    p_cb->loc_r_key &= ~SMP_SEC_KEY_TYPE_LINK;
    /*send key ready evt for encryption setup*/
    key.key_type = SMP_KEY_TYPE_LTK;
    key.p_data =  p_cb->ltk;
    smp_sm_event(p_cb, SMP_KEY_READY_EVT, &key);
}

/*******************************************************************************
**
** Function         smp_generate_rpa
**
** Description      This function is called to generate RPA for derived LTK
**                  for LE SC if a new node needs to be created.
**
** Returns          void
**
*******************************************************************************/
void smp_generate_rpa(tSMP_CB* p_cb, BT_OCTET16 rem_irk)
{
    tSMP_ENC    output;
    SMP_TRACE_DEBUG("%s", __FUNCTION__);

    p_cb->rand[2] &= (~BLE_RESOLVE_ADDR_MASK);
    p_cb->rand[2] |= BLE_RESOLVE_ADDR_MSB;

    p_cb->private_addr[2] = p_cb->rand[0];
    p_cb->private_addr[1] = p_cb->rand[1];
    p_cb->private_addr[0] = p_cb->rand[2];

    if (SMP_Encrypt(rem_irk, BT_OCTET16_LEN, p_cb->rand, 3, &output))
    {
        p_cb->private_addr[5] = output.param_buf[0];
        p_cb->private_addr[4] = output.param_buf[1];
        p_cb->private_addr[3] = output.param_buf[2];
    }
}
#endif
/*******************************************************************************
**
** Function         smp_genenrate_rand_cont
**
** Description      This function is called to generate another 64 bits random for
**                  MRand or Srand.
**
** Returns          void
**
*******************************************************************************/
void smp_genenrate_rand_cont(tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    UNUSED(p_data);

    SMP_TRACE_DEBUG ("smp_genenrate_rand_cont ");
    p_cb->rand_enc_proc = SMP_GEN_SRAND_MRAND_CONT;
    /* generate 64 MSB of MRand or SRand */

    if (!btsnd_hcic_ble_rand((void *)smp_rand_back))
        smp_rand_back(NULL);
}
/*******************************************************************************
**
** Function         smp_generate_ltk
**
** Description      This function is called to calculate LTK, starting with DIV
**                  generation.
**
**
** Returns          void
**
*******************************************************************************/
void smp_generate_ltk(tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    BOOLEAN     div_status;
    UNUSED(p_data);

    SMP_TRACE_DEBUG ("smp_generate_ltk ");

    div_status = btm_get_local_div(p_cb->pairing_bda, &p_cb->div);

    if (div_status)
    {
        smp_genenrate_ltk_cont(p_cb, NULL);
    }
    else
    {
        SMP_TRACE_DEBUG ("Generate DIV for LTK");
        p_cb->rand_enc_proc = SMP_GEN_DIV_LTK;
        /* generate MRand or SRand */
        if (!btsnd_hcic_ble_rand((void *)smp_rand_back))
            smp_rand_back(NULL);
    }
}


/*******************************************************************************
**
** Function         smp_compute_csrk
**
** Description      This function is called to calculate CSRK
**
**
** Returns          void
**
*******************************************************************************/
void smp_compute_csrk(tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    BT_OCTET16  er;
    UINT8       buffer[4]; /* for (r || DIV)  r=1*/
    UINT16      r=1;
    UINT8       *p=buffer;
    tSMP_ENC    output;
    tSMP_STATUS   status = SMP_PAIR_FAIL_UNKNOWN;
    UNUSED(p_data);

    SMP_TRACE_DEBUG ("smp_compute_csrk div=%x", p_cb->div);
    BTM_GetDeviceEncRoot(er);
    /* CSRK = d1(ER, DIV, 1) */
    UINT16_TO_STREAM(p, p_cb->div);
    UINT16_TO_STREAM(p, r);

    if (!SMP_Encrypt(er, BT_OCTET16_LEN, buffer, 4, &output))
    {
        SMP_TRACE_ERROR("smp_generate_csrk failed");
        smp_sm_event(p_cb, SMP_AUTH_CMPL_EVT, &status);
    }
    else
    {
        memcpy((void *)p_cb->csrk, output.param_buf, BT_OCTET16_LEN);
        smp_send_csrk_info(p_cb, NULL);
    }
}

/*******************************************************************************
**
** Function         smp_generate_csrk
**
** Description      This function is called to calculate LTK, starting with DIV
**                  generation.
**
**
** Returns          void
**
*******************************************************************************/
void smp_generate_csrk(tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    BOOLEAN     div_status;
    UNUSED(p_data);

    SMP_TRACE_DEBUG ("smp_generate_csrk");

    div_status = btm_get_local_div(p_cb->pairing_bda, &p_cb->div);
    if (div_status)
    {
        smp_compute_csrk(p_cb, NULL);
    }
    else
    {
        SMP_TRACE_DEBUG ("Generate DIV for CSRK");
        p_cb->rand_enc_proc = SMP_GEN_DIV_CSRK;
        if (!btsnd_hcic_ble_rand((void *)smp_rand_back))
            smp_rand_back(NULL);
    }
}


/*******************************************************************************
** Function         smp_concatenate_peer
**                  add pairing command sent from local device into p1.
*******************************************************************************/
void smp_concatenate_local( tSMP_CB *p_cb, UINT8 **p_data, UINT8 op_code)
{
    UINT8   *p = *p_data;

    SMP_TRACE_DEBUG ("smp_concatenate_local ");
    UINT8_TO_STREAM(p, op_code);
    UINT8_TO_STREAM(p, p_cb->loc_io_caps);
    UINT8_TO_STREAM(p, p_cb->loc_oob_flag);
    UINT8_TO_STREAM(p, p_cb->loc_auth_req);
    UINT8_TO_STREAM(p, p_cb->loc_enc_size);
    UINT8_TO_STREAM(p, p_cb->loc_i_key);
    UINT8_TO_STREAM(p, p_cb->loc_r_key);

    *p_data = p;
}
/*******************************************************************************
** Function         smp_concatenate_peer
**                  add pairing command received from peer device into p1.
*******************************************************************************/
void smp_concatenate_peer( tSMP_CB *p_cb, UINT8 **p_data, UINT8 op_code)
{
    UINT8   *p = *p_data;

    SMP_TRACE_DEBUG ("smp_concatenate_peer ");
    UINT8_TO_STREAM(p, op_code);
    UINT8_TO_STREAM(p, p_cb->peer_io_caps);
    UINT8_TO_STREAM(p, p_cb->peer_oob_flag);
    UINT8_TO_STREAM(p, p_cb->peer_auth_req);
    UINT8_TO_STREAM(p, p_cb->peer_enc_size);
    UINT8_TO_STREAM(p, p_cb->peer_i_key);
    UINT8_TO_STREAM(p, p_cb->peer_r_key);

    *p_data = p;
}
/*******************************************************************************
**
** Function         smp_gen_p1_4_confirm
**
** Description      Generate Confirm/Compare Step1:
**                  p1 = pres || preq || rat' || iat'
**
** Returns          void
**
*******************************************************************************/
void smp_gen_p1_4_confirm( tSMP_CB *p_cb, BT_OCTET16 p1)
{
    UINT8 *p = (UINT8 *)p1;
    tBLE_ADDR_TYPE    addr_type = 0;
    BD_ADDR           remote_bda;

    SMP_TRACE_DEBUG ("smp_gen_p1_4_confirm");

    if (!BTM_ReadRemoteConnectionAddr(p_cb->pairing_bda, remote_bda, &addr_type))
    {
        SMP_TRACE_ERROR("can not generate confirm for unknown device");
        return;
    }

    BTM_ReadConnectionAddr( p_cb->pairing_bda, p_cb->local_bda, &p_cb->addr_type);

    if (p_cb->role == HCI_ROLE_MASTER)
    {
        /* LSB : rat': initiator's(local) address type */
        UINT8_TO_STREAM(p, p_cb->addr_type);
        /* LSB : iat': responder's address type */
        UINT8_TO_STREAM(p, addr_type);
        /* concatinate preq */
        smp_concatenate_local(p_cb, &p, SMP_OPCODE_PAIRING_REQ);
        /* concatinate pres */
        smp_concatenate_peer(p_cb, &p, SMP_OPCODE_PAIRING_RSP);
    }
    else
    {
        /* LSB : iat': initiator's address type */
        UINT8_TO_STREAM(p, addr_type);
        /* LSB : rat': responder's(local) address type */
        UINT8_TO_STREAM(p, p_cb->addr_type);
        /* concatinate preq */
        smp_concatenate_peer(p_cb, &p, SMP_OPCODE_PAIRING_REQ);
        /* concatinate pres */
        smp_concatenate_local(p_cb, &p, SMP_OPCODE_PAIRING_RSP);
    }
#if SMP_DEBUG == TRUE
    SMP_TRACE_DEBUG("p1 = pres || preq || rat' || iat'");
    smp_debug_print_nbyte_little_endian ((UINT8 *)p1, (const UINT8 *)"P1", 16);
#endif
}
/*******************************************************************************
**
** Function         smp_gen_p2_4_confirm
**
** Description      Generate Confirm/Compare Step2:
**                  p2 = padding || ia || ra
**
** Returns          void
**
*******************************************************************************/
void smp_gen_p2_4_confirm( tSMP_CB *p_cb, BT_OCTET16 p2)
{
    UINT8       *p = (UINT8 *)p2;
    BD_ADDR     remote_bda;
    tBLE_ADDR_TYPE  addr_type = 0;

    if (!BTM_ReadRemoteConnectionAddr(p_cb->pairing_bda, remote_bda, &addr_type))
    {
        SMP_TRACE_ERROR("can not generate confirm p2 for unknown device");
        return;
    }

    SMP_TRACE_DEBUG ("smp_gen_p2_4_confirm");

    memset(p, 0, sizeof(BT_OCTET16));

    if (p_cb->role == HCI_ROLE_MASTER)
    {
        /* LSB ra */
        BDADDR_TO_STREAM(p, remote_bda);
        /* ia */
        BDADDR_TO_STREAM(p, p_cb->local_bda);
    }
    else
    {
        /* LSB ra */
        BDADDR_TO_STREAM(p, p_cb->local_bda);
        /* ia */
        BDADDR_TO_STREAM(p, remote_bda);
    }
#if SMP_DEBUG == TRUE
    SMP_TRACE_DEBUG("p2 = padding || ia || ra");
    smp_debug_print_nbyte_little_endian(p2, (const UINT8 *)"p2", 16);
#endif
}
/*******************************************************************************
**
** Function         smp_calculate_comfirm
**
** Description      This function is called to calculate Confirm value.
**
** Returns          void
**
*******************************************************************************/
void smp_calculate_comfirm (tSMP_CB *p_cb, BT_OCTET16 rand, BD_ADDR bda)
{
    BT_OCTET16      p1;
    tSMP_ENC       output;
    tSMP_STATUS     status = SMP_PAIR_FAIL_UNKNOWN;
    UNUSED(bda);

    SMP_TRACE_DEBUG ("smp_calculate_comfirm ");
    /* generate p1 = pres || preq || rat' || iat' */
    smp_gen_p1_4_confirm(p_cb, p1);

    /* p1 = rand XOR p1 */
    smp_xor_128(p1, rand);

    smp_debug_print_nbyte_little_endian ((UINT8 *)p1, (const UINT8 *)"P1' = r XOR p1", 16);

    /* calculate e(k, r XOR p1), where k = TK */
    if (!SMP_Encrypt(p_cb->tk, BT_OCTET16_LEN, p1, BT_OCTET16_LEN, &output))
    {
        SMP_TRACE_ERROR("smp_generate_csrk failed");
        smp_sm_event(p_cb, SMP_AUTH_CMPL_EVT, &status);
    }
    else
    {
        smp_calculate_comfirm_cont(p_cb, &output);
    }
}
/*******************************************************************************
**
** Function         smp_calculate_comfirm_cont
**
** Description      This function is called when SConfirm/MConfirm is generated
**                  proceed to send the Confirm request/response to peer device.
**
** Returns          void
**
*******************************************************************************/
static void smp_calculate_comfirm_cont(tSMP_CB *p_cb, tSMP_ENC *p)
{
    BT_OCTET16    p2;
    tSMP_ENC      output;
    tSMP_STATUS     status = SMP_PAIR_FAIL_UNKNOWN;

    SMP_TRACE_DEBUG ("smp_calculate_comfirm_cont ");
#if SMP_DEBUG == TRUE
    SMP_TRACE_DEBUG("Confirm step 1 p1' = e(k, r XOR p1)  Generated");
    smp_debug_print_nbyte_little_endian (p->param_buf, (const UINT8 *)"C1", 16);
#endif

    smp_gen_p2_4_confirm(p_cb, p2);

    /* calculate p2 = (p1' XOR p2) */
    smp_xor_128(p2, p->param_buf);
    smp_debug_print_nbyte_little_endian ((UINT8 *)p2, (const UINT8 *)"p2' = C1 xor p2", 16);

    /* calculate: Confirm = E(k, p1' XOR p2) */
    if (!SMP_Encrypt(p_cb->tk, BT_OCTET16_LEN, p2, BT_OCTET16_LEN, &output))
    {
        SMP_TRACE_ERROR("smp_calculate_comfirm_cont failed");
        smp_sm_event(p_cb, SMP_AUTH_CMPL_EVT, &status);
    }
    else
    {
        switch (p_cb->rand_enc_proc)
        {
            case SMP_GEN_CONFIRM:
                smp_process_confirm(p_cb, &output);
                break;

            case SMP_GEN_COMPARE:
                smp_process_compare(p_cb, &output);
                break;
        }
    }
}
/*******************************************************************************
**
** Function         smp_genenrate_confirm
**
** Description      This function is called when a 48 bits random number is generated
**                  as SRand or MRand, continue to calculate Sconfirm or MConfirm.
**
** Returns          void
**
*******************************************************************************/
static void smp_genenrate_confirm(tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    UNUSED(p_data);

    SMP_TRACE_DEBUG ("smp_genenrate_confirm ");
    p_cb->rand_enc_proc = SMP_GEN_CONFIRM;

    smp_debug_print_nbyte_little_endian ((UINT8 *)p_cb->rand,  (const UINT8 *)"local rand", 16);

    smp_calculate_comfirm(p_cb, p_cb->rand, p_cb->pairing_bda);
}
/*******************************************************************************
**
** Function         smp_generate_compare
**
** Description      This function is called to generate SConfirm for Slave device,
**                  or MSlave for Master device. This function can be also used for
**                  generating Compare number for confirm value check.
**
** Returns          void
**
*******************************************************************************/
void smp_generate_compare (tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    UNUSED(p_data);

    SMP_TRACE_DEBUG ("smp_generate_compare ");

#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
    if(p_cb->is_secure) /*for secure connections*/
    {
        smp_verify_sc_confirm(p_cb, p_data);
        return;
    }
#endif
    p_cb->rand_enc_proc = SMP_GEN_COMPARE;

    smp_debug_print_nbyte_little_endian ((UINT8 *)p_cb->rrand,  (const UINT8 *)"peer rand", 16);

    smp_calculate_comfirm(p_cb, p_cb->rrand, p_cb->local_bda);
}
/*******************************************************************************
**
** Function         smp_process_confirm
**
** Description      This function is called when SConfirm/MConfirm is generated
**                  proceed to send the Confirm request/response to peer device.
**
** Returns          void
**
*******************************************************************************/
static void smp_process_confirm(tSMP_CB *p_cb, tSMP_ENC *p)
{
    tSMP_KEY    key;

    SMP_TRACE_DEBUG ("smp_process_confirm ");
#if SMP_CONFORMANCE_TESTING == TRUE
    if (p_cb->enable_test_confirm_val)
    {
        BTM_TRACE_DEBUG ("Use confirm value from script");
        memcpy(p_cb->confirm, p_cb->test_confirm, BT_OCTET16_LEN);
    }
    else
        memcpy(p_cb->confirm, p->param_buf, BT_OCTET16_LEN);
#else
    memcpy(p_cb->confirm, p->param_buf, BT_OCTET16_LEN);
#endif


#if (SMP_DEBUG == TRUE)
    SMP_TRACE_DEBUG("Confirm  Generated");
    smp_debug_print_nbyte_little_endian ((UINT8 *)p_cb->confirm,  (const UINT8 *)"Confirm", 16);
#endif

    key.key_type = SMP_KEY_TYPE_CFM;
    key.p_data = p->param_buf;

    smp_sm_event(p_cb, SMP_KEY_READY_EVT, &key);
}
/*******************************************************************************
**
** Function         smp_process_compare
**
** Description      This function is called when Compare is generated using the
**                  RRand and local BDA, TK information.
**
** Returns          void
**
*******************************************************************************/
static void smp_process_compare(tSMP_CB *p_cb, tSMP_ENC *p)
{
    tSMP_KEY    key;

    SMP_TRACE_DEBUG ("smp_process_compare ");
#if (SMP_DEBUG == TRUE)
    SMP_TRACE_DEBUG("Compare Generated");
    smp_debug_print_nbyte_little_endian (p->param_buf,  (const UINT8 *)"Compare", 16);
#endif
    key.key_type = SMP_KEY_TYPE_CMP;
    key.p_data   = p->param_buf;

    smp_sm_event(p_cb, SMP_KEY_READY_EVT, &key);
}

/*******************************************************************************
**
** Function         smp_process_stk
**
** Description      This function is called when STK is generated
**                  proceed to send the encrypt the link using STK.
**
** Returns          void
**
*******************************************************************************/
static void smp_process_stk(tSMP_CB *p_cb, tSMP_ENC *p)
{
    tSMP_KEY    key;

    SMP_TRACE_DEBUG ("smp_process_stk ");
#if (SMP_DEBUG == TRUE)
    SMP_TRACE_ERROR("STK Generated");
#endif
    smp_mask_enc_key(p_cb->loc_enc_size, p->param_buf);

    key.key_type = SMP_KEY_TYPE_STK;
    key.p_data   = p->param_buf;

    smp_sm_event(p_cb, SMP_KEY_READY_EVT, &key);
}

/*******************************************************************************
**
** Function         smp_genenrate_ltk_cont
**
** Description      This function is to calculate LTK = d1(ER, DIV, 0)= e(ER, DIV)
**
** Returns          void
**
*******************************************************************************/
static void smp_genenrate_ltk_cont(tSMP_CB *p_cb, tSMP_INT_DATA *p_data)
{
    BT_OCTET16  er;
    tSMP_ENC    output;
    tSMP_STATUS     status = SMP_PAIR_FAIL_UNKNOWN;
    UNUSED(p_data);

    SMP_TRACE_DEBUG ("smp_genenrate_ltk_cont ");
    BTM_GetDeviceEncRoot(er);

    /* LTK = d1(ER, DIV, 0)= e(ER, DIV)*/
    if (!SMP_Encrypt(er, BT_OCTET16_LEN, (UINT8 *)&p_cb->div,
                     sizeof(UINT16), &output))
    {
        SMP_TRACE_ERROR("smp_genenrate_ltk_cont failed");
        smp_sm_event(p_cb, SMP_AUTH_CMPL_EVT, &status);
    }
    else
    {
        /* mask the LTK */
        smp_mask_enc_key(p_cb->loc_enc_size, output.param_buf);
        memcpy((void *)p_cb->ltk, output.param_buf, BT_OCTET16_LEN);
        smp_generate_rand_vector(p_cb, NULL);
    }

}

/*******************************************************************************
**
** Function         smp_generate_y
**
** Description      This function is to proceed generate Y = E(DHK, Rand)
**
** Returns          void
**
*******************************************************************************/
static void smp_generate_y(tSMP_CB *p_cb, tSMP_INT_DATA *p)
{
    BT_OCTET16  dhk;
    tSMP_ENC   output;
    tSMP_STATUS     status = SMP_PAIR_FAIL_UNKNOWN;
    UNUSED(p);

    SMP_TRACE_DEBUG ("smp_generate_y ");
    BTM_GetDeviceDHK(dhk);

    if (!SMP_Encrypt(dhk, BT_OCTET16_LEN, p_cb->enc_rand,
                     BT_OCTET8_LEN, &output))
    {
        SMP_TRACE_ERROR("smp_generate_y failed");
        smp_sm_event(p_cb, SMP_AUTH_CMPL_EVT, &status);
    }
    else
    {
        smp_process_ediv(p_cb, &output);
    }
}
/*******************************************************************************
**
** Function         smp_generate_rand_vector
**
** Description      This function is called when LTK is generated, send state machine
**                  event to SMP.
**
** Returns          void
**
*******************************************************************************/
static void smp_generate_rand_vector (tSMP_CB *p_cb, tSMP_INT_DATA *p)
{
    UNUSED(p);

    /* generate EDIV and rand now */
    /* generate random vector */
    SMP_TRACE_DEBUG ("smp_generate_rand_vector ");
    p_cb->rand_enc_proc = SMP_GEN_RAND_V;
    if (!btsnd_hcic_ble_rand((void *)smp_rand_back))
        smp_rand_back(NULL);

}
/*******************************************************************************
**
** Function         smp_genenrate_smp_process_edivltk_cont
**
** Description      This function is to calculate EDIV = Y xor DIV
**
** Returns          void
**
*******************************************************************************/
static void smp_process_ediv(tSMP_CB *p_cb, tSMP_ENC *p)
{
    tSMP_KEY    key;
    UINT8 *pp= p->param_buf;
    UINT16  y;

    SMP_TRACE_DEBUG ("smp_process_ediv ");
    STREAM_TO_UINT16(y, pp);

    /* EDIV = Y xor DIV */
    p_cb->ediv = p_cb->div ^ y;
    /* send LTK ready */
    SMP_TRACE_ERROR("LTK ready");
    key.key_type = SMP_KEY_TYPE_LTK;
    key.p_data   = p->param_buf;

    smp_sm_event(p_cb, SMP_KEY_READY_EVT, &key);
}

/*******************************************************************************
**
** Function         smp_rand_back
**
** Description      This function is to process the rand command finished,
**                  process the random/encrypted number for further action.
**
** Returns          void
**
*******************************************************************************/
static void smp_rand_back(tBTM_RAND_ENC *p)
{
    tSMP_CB *p_cb = &smp_cb;
    UINT8   *pp = p->param_buf;
    UINT8   failure = SMP_PAIR_FAIL_UNKNOWN;
    UINT8   state = p_cb->rand_enc_proc & ~0x80;

    SMP_TRACE_DEBUG ("smp_rand_back state=0x%x", state);
    if (p && p->status == HCI_SUCCESS)
    {
        switch (state)
        {

            case SMP_GEN_SRAND_MRAND:
                memcpy((void *)p_cb->rand, p->param_buf, p->param_len);
                smp_genenrate_rand_cont(p_cb, NULL);
                break;

            case SMP_GEN_SRAND_MRAND_CONT:
                memcpy((void *)&p_cb->rand[8], p->param_buf, p->param_len);
#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
                if(smp_get_state() == SMP_ST_IDLE)/*OOB generation*/
                {
                    smp_generate_oob_confirm(p_cb);
                    break;
                }
                if(p_cb->is_secure && p_cb->model == SMP_MODEL_OOB &&  p_cb->role == HCI_ROLE_SLAVE)
                {
                    /*send a dummy init evt if it is already recvd*/
                    if(p_cb->flags & SMP_PAIR_FLAGS_CMD_INIT)
                    {
                        smp_set_state(SMP_ST_WAIT_NONCE);
                        smp_sm_event(p_cb, SMP_RAND_EVT, NULL);
                    }
                }
                else if(p_cb->is_secure &&
                   (p_cb->role == HCI_ROLE_SLAVE || p_cb->model == SMP_MODEL_PASSKEY || p_cb->model == SMP_MODEL_KEY_NOTIF))
                {
                    smp_generate_sc_confirm(p_cb, NULL);
                }
                else if(p_cb->is_secure && p_cb->role == HCI_ROLE_MASTER)
                {
                    smp_send_init(p_cb, NULL);
                }
                if(!p_cb->is_secure)
                {
#endif
                    smp_genenrate_confirm(p_cb, NULL);
#if (defined BTM_LE_SECURE_CONN && BTM_LE_SECURE_CONN == TRUE)
                }
#endif
                break;

            case SMP_GEN_DIV_LTK:
                STREAM_TO_UINT16(p_cb->div, pp);
                smp_genenrate_ltk_cont(p_cb, NULL);
                break;

            case SMP_GEN_DIV_CSRK:
                STREAM_TO_UINT16(p_cb->div, pp);
                smp_compute_csrk(p_cb, NULL);
                break;

            case SMP_GEN_TK:
                smp_proc_passkey(p_cb, p);
                break;

            case SMP_GEN_RAND_V:
                memcpy(p_cb->enc_rand, p->param_buf, BT_OCTET8_LEN);
                smp_generate_y(p_cb, NULL);
                break;

        }

        return;
    }

    SMP_TRACE_ERROR("smp_rand_back Key generation failed: (%d)", p_cb->rand_enc_proc);

    smp_sm_event(p_cb, SMP_AUTH_CMPL_EVT, &failure);

}
#endif

