/*
 * Copyright (c) 2015, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *        * Redistributions of source code must retain the above copyright
 *            notice, this list of conditions and the following disclaimer.
 *        * Redistributions in binary form must reproduce the above copyright
 *            notice, this list of conditions and the following disclaimer in the
 *            documentation and/or other materials provided with the distribution.
 *        * Neither the name of The Linux Foundation nor
 *            the names of its contributors may be used to endorse or promote
 *            products derived from this software without specific prior written
 *            permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NON-INFRINGEMENT ARE DISCLAIMED.    IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "aes.h"
#include <stdlib.h>
#include "bt_target.h"
#include <stdio.h>
#include "gki.h"
#define BLOCK_SIZE 16
#define KEY_SIZE 16
#define AES_TRACE_DEBUG(...)       {BT_TRACE(TRACE_LAYER_SMP, TRACE_TYPE_DEBUG, ##__VA_ARGS__);}
const UINT8 Rb[BLOCK_SIZE] = {
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
                             };
const UINT8 block_zero[BLOCK_SIZE] = {
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                             };

UINT8 salt[BLOCK_SIZE] = {
                                0x6C, 0x88, 0x83, 0x91, 0xAA, 0xF5, 0xA5, 0x38,
                                0x60, 0x37, 0x0B, 0xDB, 0x5A, 0x60, 0x83, 0xBE
                               };

static void smp_debug_print_nbyte_little_endian (UINT8 *p, const UINT8 *key_name, UINT8 len)
{
    int     i, x = 0, s = 0;
    UINT8   p_buf[300];
    memset(p_buf, 0, 300);
    s = sizeof(p_buf);

    for (i = 0; i < len; i ++)
    {
        x += snprintf ((char *)&p_buf[x], s-x, "%02x ", p[i]);
    }
    AES_TRACE_DEBUG("%s(MSB ~ LSB) = %s\n", key_name, p_buf);
}

static void block_xor_gate(const UINT8* p1, const UINT8* p2, UINT8* p_out)
{
    UINT8 index;
    for(index = 0; index < BLOCK_SIZE; index++)
    {
        p_out[index] = p1[index] ^ p2[index];
    }
}

static void block_left_shift(const UINT8 *p, UINT8* p_out)
{
    UINT8 index;
    for(index = 0; index < BLOCK_SIZE-1; index ++)
    {
        p_out[index] = (p[index] << 1) | (((p[index + 1]) & 0x80) >> 7);
    }
    p_out[index] = p[index] << 1;
}

static UINT16 block_ceil(UINT16 len)
{
    UINT8 q = len/BLOCK_SIZE;
    UINT8 r = len%BLOCK_SIZE;
    if(r == 0)
        return q;
    else
        return q+1;
}

static void generate_subKey(UINT8 *p_key, UINT8 *p_key1, UINT8* p_key2)
{
    UINT8 p_temp[BLOCK_SIZE] = {0};
    aes_context ctx;
    UINT8 key_in[KEY_SIZE] = {0};

    /* AES 128 (key, 0) */
    aes_set_key(p_key, KEY_SIZE, &ctx);
    aes_encrypt(block_zero, key_in, &ctx);

    /* Key1 gen */
    if(key_in[0] & 0x80) /*MSB is not zero*/
    {
        block_left_shift(key_in, p_temp);
        block_xor_gate(Rb, p_temp, p_key1);
    }
    else
    {
        block_left_shift(key_in, p_key1);
    }
    /* Key2 gen */
    if(p_key1[0] & 0x80) /* MSB is not zero */
    {
        block_left_shift(p_key1, p_temp);
        block_xor_gate(Rb, p_temp, p_key2);
    }
    else
    {
        block_left_shift(p_key1, p_key2);
    }
}


void aes_cmac(UINT8 *p, UINT8 *p_key, UINT16 text_len, UINT8 *p_out)
{
    UINT8 p_key1[BLOCK_SIZE];
    UINT8 p_key2[BLOCK_SIZE];
    UINT8 block_n[BLOCK_SIZE] = {0};/*last block*/
    UINT8 block_y[BLOCK_SIZE] = {0};/*intermediate block XOR(input, output of last rnd)*/
    UINT8 *p_head, *p_last = NULL;
    UINT16 num_blocks;
    UINT8 rem_octets;
    UINT16 index;
    aes_context ctx;

    memset(p_out, 0, BLOCK_SIZE); /*output*/

    if(p == NULL)
        return;

    if(p && text_len)
        smp_debug_print_nbyte_little_endian(p, (const UINT8 *)"original byte", text_len);

    AES_TRACE_DEBUG("%s:%d", __FUNCTION__, text_len);

    smp_debug_print_nbyte_little_endian(p_key, (const UINT8 *)"key byte", BLOCK_SIZE);
    generate_subKey(p_key, p_key1, p_key2);

    smp_debug_print_nbyte_little_endian(p_key1, (const UINT8 *)"key1 byte", BLOCK_SIZE);
    smp_debug_print_nbyte_little_endian(p_key2, (const UINT8 *)"key2 byte", BLOCK_SIZE);

    num_blocks = block_ceil(text_len);
    rem_octets = text_len % BLOCK_SIZE;
    if(num_blocks)
    {
        /* point to the last block*/
        p_last = p + BLOCK_SIZE * (num_blocks - 1);
    }
    if(rem_octets != 0 || !num_blocks) /*need padding*/
    {
        if(p_last)
            memcpy(block_n, p_last, rem_octets);
        block_n[rem_octets] = 0x80;
        block_xor_gate(block_n, p_key2, block_n);
    }
    else
    {
        memcpy(block_n, p_last, BLOCK_SIZE);
        block_xor_gate(block_n, p_key1, block_n);
    }

    for(index = 0; index < num_blocks - 1 && num_blocks > 0; index++)
    {
        p_head = p + BLOCK_SIZE * index;
        block_xor_gate(p_head, p_out, block_y);
        /* AES 128 (key, 0) */
        aes_set_key(p_key, KEY_SIZE, &ctx);
        aes_encrypt(block_y, p_out, &ctx);
    }

    /*process the last block now*/
    block_xor_gate(block_n, p_out, block_y);
    aes_set_key(p_key, KEY_SIZE, &ctx);
    aes_encrypt(block_y, p_out, &ctx);

    smp_debug_print_nbyte_little_endian(p_out, (const UINT8 *)"AES_CMAC", BLOCK_SIZE);
}

void aes_f4(UINT8* p_u, UINT8* p_v, UINT8* p_x, UINT8* p_z, UINT8* p_out)
{
    /*
     U is 256 bits (32 octets)
     V is 256 bits (32 octets)
     X is 128 bits (16 octets)
     Z is 8 bits   (1 octet)
    */

    UINT8 p_rev_key[BLOCK_SIZE];
    UINT8 *p_cat = (UINT8 *) GKI_getbuf(sizeof(UINT8) * 65);
    if(p_cat == NULL)
        return ;
    UINT8 index;
    UINT8 vector_len = 32;
    memset(p_cat, 0, sizeof(UINT8) * (vector_len*2 + 1));

    for(index = 0; index < vector_len; index ++)
    {
        p_cat[index] = p_u[index];
        p_cat[index + vector_len] = p_v[index];
    }
    p_cat[index + vector_len] = *p_z;

    aes_cmac(p_cat, p_x, vector_len*2 + 1, p_out);
    smp_debug_print_nbyte_little_endian(p_out, (const UINT8 *)"---f4---", BLOCK_SIZE);
    GKI_freebuf(p_cat);
}

void aes_f5(UINT8 *p_w, UINT8 *p_n1, UINT8 *p_n2, UINT8 *p_keyID, UINT8 *p_a1, UINT8* p_a2, UINT8* p_out)
{
    /*
      W is 128 bits (16 octets)
      N1 is 128 bits (16 octets)
      N2 is 128 bits (16 octets)
      KeyID is 32 bits (4 octets)
      A1, A2 are 56 bits (7 octets)*/

    UINT8 n_len = 16;
    UINT8 keyid_len = 4;
    UINT8 bda_len = 7;
    UINT8 index;
    UINT8 *p_cat = (UINT8 *) GKI_getbuf(sizeof(UINT8) * (n_len*2 + keyid_len + bda_len*2));
    if(p_cat == NULL)
        return ;
    memset(p_cat, 0, sizeof(UINT8) * (n_len*2 + keyid_len + bda_len*2));
    for(index = 0; index < n_len; index ++)
    {
        p_cat[index] = p_n1[index];
        p_cat[index + n_len] = p_n2[index];
        if(index < keyid_len)
        {
            p_cat[index + n_len*2] = p_keyID[index];
        }
        if(index < bda_len)
        {
            p_cat[index + n_len*2 + keyid_len] = p_a1[index];
            p_cat[index + n_len*2 + keyid_len + bda_len] = p_a2[index];
        }
    }
    aes_cmac(p_cat, p_w, n_len*2 + keyid_len + bda_len*2, p_out);
    GKI_freebuf(p_cat);
    smp_debug_print_nbyte_little_endian(p_out, (const UINT8 *)"---f5---", BLOCK_SIZE);
}

void aes_f5_v2(UINT8 counter, UINT8 *p_w, UINT8 *p_n1, UINT8 *p_n2, UINT8 *p_keyID, UINT8 *p_a1, UINT8* p_a2, UINT8* p_out)
{
    /*
      W is 256 bits (16 octets)
      N1 is 128 bits (16 octets)
      N2 is 128 bits (16 octets)
      KeyID is 32 bits (4 octets)*/
    UINT8 t_key[BLOCK_SIZE] = {0};
    UINT8 n_len = 16;
    UINT8 keyid_len = 4;
    UINT8 bda_len = 7;
    UINT8 index;
    UINT8 *p_cat = (UINT8 *) GKI_getbuf(sizeof(UINT8) * (n_len*2 + keyid_len + bda_len*2 + 3));
    if(p_cat == NULL)
        return ;
    memset(p_cat, 0, sizeof(UINT8) * (n_len*2 + keyid_len + bda_len*2 + 3)); /*additional 3 for counter and len*/

    aes_cmac(p_w, salt, n_len*2, t_key); /*t_key is the key for the f5 calc */

    smp_debug_print_nbyte_little_endian(t_key, (const UINT8 *)"---T---", BLOCK_SIZE);
    /* counter = 0 p_cat[0] = 0x00 */
    p_cat[0] = counter;
    for(index = 1; index < n_len + 1; index ++)
    {
        if(index - 1 < keyid_len)
        {
            p_cat[index] = p_keyID[index-1];
        }
        p_cat[index + keyid_len] = p_n1[index-1];
        p_cat[index + keyid_len + n_len] = p_n2[index-1];
        if(index - 1 < bda_len)
        {
            p_cat[index + n_len*2 + keyid_len] = p_a1[index-1];
            p_cat[index + n_len*2 + keyid_len + bda_len] = p_a2[index-1];
        }
    }
    p_cat[n_len*2 + keyid_len + bda_len*2 + 1] = 0x01;
    aes_cmac(p_cat, t_key, n_len*2 + keyid_len + bda_len*2 + 3, p_out);
    smp_debug_print_nbyte_little_endian(p_out, (const UINT8 *)"---f5_v2---", BLOCK_SIZE);
}

void aes_f6(UINT8 *p_w, UINT8 *p_n1, UINT8 *p_n2, UINT8 *p_r, UINT8 *p_iocap, UINT8 *p_a1, UINT8 * p_a2, UINT8 * p_out)
{
    /*
    W is 128 bits (16 octets) -> KEY
    N1, N2 are 128 bits (16 octets)
    R is 128 bits (16 octets)
    IO cap is 24 bits (3 octets)
    A1,A2 is 56 bits (7 octets)
    */

    UINT8 n_len = 16;
    UINT8 r_len = 16;
    UINT8 io_len = 3;
    UINT8 bda_len = 7;
    UINT8 index;
    UINT8 *p_cat = (UINT8 *) GKI_getbuf(sizeof(UINT8) * (n_len*2 + r_len + io_len + bda_len*2));

    if(p_cat == NULL)
        return ;
    memset(p_cat, 0, sizeof(UINT8) * (n_len*2 + r_len + io_len + bda_len*2));

    for(index = 0; index < n_len; index ++)
    {
        p_cat[index] = p_n1[index];
        p_cat[index + n_len] = p_n2[index];
        p_cat[index + n_len*2] = p_r[index];

        if(index < io_len)
        {
            p_cat[index + n_len*2 + r_len] = p_iocap[index];
        }
        if(index < bda_len)
        {
            p_cat[index + n_len*2 + r_len + io_len] = p_a1[index];
            p_cat[index + n_len*2 + r_len + io_len + bda_len] = p_a2[index];
        }
    }

    aes_cmac(p_cat, p_w, n_len*2 + r_len + io_len + bda_len*2, p_out);
    GKI_freebuf(p_cat);
}

void aes_g2(UINT8 *p_u, UINT8 *p_v, UINT8 *p_x, UINT8 *p_y, UINT8 *p_out)
{
    /*
    U,V are 256 bits (32 octets)
    X,Y are 128 bits (16 octets)
    */
    UINT8 u_len = 32;
    UINT8 x_len = 16;
    UINT8 mod32_len = 4;
    UINT8 cmac[BLOCK_SIZE];
    UINT8 index;
    UINT8 *p_cat = (UINT8 *) GKI_getbuf(sizeof(UINT8) * (u_len*2 + x_len));

    if(p_cat == NULL)
        return ;
    memset(p_cat, 0, sizeof(UINT8) * (u_len*2 + x_len));
    for(index = 0; index < u_len; index ++)
    {
        p_cat[index] = p_u[index];
        p_cat[index + u_len] = p_v[index];
        if(index < x_len)
            p_cat[index + u_len*2] = p_y[index];
    }
    aes_cmac(p_cat, p_x, u_len*2 + x_len, cmac);
    /* mod 2^32* keep only the last 32 bits or 4bytes */
    for(index = 0; index < mod32_len; index ++)
    {
        p_out[index] = cmac[BLOCK_SIZE - mod32_len + index];
    }
    GKI_freebuf(p_cat);
}
