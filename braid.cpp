/*
* Copyright (C) 2012, 2013 naehrwert
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, version 2.0.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License 2.0 for more details.
*
* A copy of the GPL 2.0 should have been included with the program.
* If not, see http://www.gnu.org/licenses/
*/

#include <malloc.h>
#include <stdio.h>
#include <time.h>

#include "braid.h"
#include "mt19937.h"
#include "sha2.h"

/*! Invalid index. */
#define INV_IDX ((unsigned int)(0xffffffff))

/*! Hashing charset length. */
#define CHARSET_LENGTH 64

/*! Hashing charset. */
static char _charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-+:;*$/][()|";

/*! PRNG context. */
static mt19937_ctxt_t *_braid_prng;

static unsigned int _braid_get_index(braid_t *b, unsigned char item)
{
	unsigned int i = 0;

	while(i < b->length)
	{
		if(b->items[i] == item)
			return i;
		i++;
	}
	
	return INV_IDX;
}

static int _braid_swap(braid_t *b, unsigned char _in, unsigned char _out)
{
	unsigned int idx = _braid_get_index(b, _out);

	if(idx == INV_IDX)
		return 0;
	
	b->items[idx] = b->items[_in];
	b->items[_in] = _out;
	
	return 1;
}

static unsigned int _braid_prng_range(unsigned int low, unsigned int high)
{
	unsigned int res;

	do
	{
		res = mt19937_update(_braid_prng) % high;
	} while(res < low || res > high);

	return res;
}

static void _braid_xor_skey(unsigned char *dst, unsigned char *skey, unsigned char *key, unsigned int length)
{
	unsigned int i;
	for(i = 0; i < length; i++)
		dst[i] = skey[i] ^ key[i];
}

void __braid_lib_init()
{
	_braid_prng = (mt19937_ctxt_t *)malloc(sizeof(mt19937_ctxt_t));
	mt19937_init(_braid_prng, clock());
}

void __braid_lib_end()
{
	free(_braid_prng);
}

braid_t *braid_alloc(unsigned int length)
{
	braid_t *res = (braid_t *)malloc(sizeof(braid_t));

	res->items = (unsigned char *)malloc(sizeof(unsigned char) * length);
	res->length = length;

	return res;
}

void braid_free(braid_t *b)
{
	free(b->items);
	free(b);
}

void braid_print(FILE *fp, braid_t *b)
{
	unsigned int i;
	for(i = 0; i < b->length; i++)
		fprintf(fp, "%02X", b->items[i]);
}

void braid_write(FILE *fp, braid_t *b)
{
	fwrite(&b->length, sizeof(unsigned int), 1, fp);
	fwrite(b->items, sizeof(unsigned char), b->length, fp);
}

braid_t *braid_read(FILE *fp)
{
	unsigned int length;
	fread(&length, sizeof(unsigned int), 1, fp);
	braid_t *res = braid_alloc(length);
	fread(res->items, sizeof(unsigned char), length, fp);
	return res;
}

braid_t *braid_identity(braid_t *b)
{
	unsigned int i;

	for(i = 0; i < b->length; i++)
		b->items[i] = i;

	return b;
}

int braid_compare(braid_t *b1, braid_t *b2)
{
	unsigned int i;

	for(i = 0; i < b1->length; i++)
		if(b1->items[i] != b2->items[i])
			return b1->items[i] - b2->items[i];

	return 0;
}

braid_t *braid_shuffle(braid_t *b, unsigned int offset, unsigned int size)
{
	unsigned int idx1, i, j, to = _braid_prng_range(1024, 4096);

	for(j = 0; j < to; j++)
	{
		if(size == 0)
		{
			for(i = offset; i < b->length; i++)
			{
				idx1 = _braid_prng_range(offset, b->length - 1);
				_braid_swap(b, i, idx1);
			}
		}
		else
		{
			for(i = offset; i < size; i++)
			{
				idx1 = _braid_prng_range(0, size - 1);
				_braid_swap(b, i, idx1);
			}
		}
	}

	return b;
}

braid_t *braid_inverse(braid_t *dst, braid_t *b)
{
	unsigned int i;

	if(dst->length != b->length)
		return NULL;

	for(i = 0; i < b->length; i++)
		dst->items[i] = _braid_get_index(b, i);

	return dst;
}

braid_t *braid_combine(braid_t *dst, braid_t *b1, braid_t *b2)
{
	unsigned int i;

	if(dst->length != b1->length && dst->length != b2->length)
		return NULL;

	for(i = 0; i < b1->length; i++)
		dst->items[i] = b2->items[b1->items[i]];

	return dst;
}

braid_ckey_t *braid_ckey_alloc()
{
	braid_ckey_t *res = (braid_ckey_t *)malloc(sizeof(braid_ckey_t));

	res->priv = NULL;
	res->privr = NULL;
	res->pub = NULL;
	
	return res;
}

void braid_ckey_free(braid_ckey_t *ckey)
{
	if(ckey->priv != NULL)
		braid_free(ckey->priv);

	if(ckey->privr != NULL)
		braid_free(ckey->privr);

	if(ckey->pub != NULL)
		braid_free(ckey->pub);

	free(ckey);
}

void braid_ckey_write_priv(FILE *fp, braid_ckey_t *ckey)
{
	//Write K.
	braid_write(fp, ckey->K);
	//Write priv.
	braid_write(fp, ckey->priv);
}

void braid_ckey_read_priv(FILE *fp, braid_ckey_t *ckey)
{
	//Read K.
	braid_t *K = braid_read(fp);
	//Read priv.
	braid_t *priv = braid_read(fp);
	//Generate the crypto key.
	braid_ckey_generate(ckey, priv, K);
}

void braid_ckey_write_pub(FILE *fp, braid_ckey_t *ckey)
{
	//Write K.
	braid_write(fp, ckey->K);
	//Write pub.
	braid_write(fp, ckey->pub);
}

void braid_ckey_read_pub(FILE *fp, braid_ckey_t *ckey)
{
	//Read K.
	ckey->K = braid_read(fp);
	//Read pub.
	ckey->pub = braid_read(fp);
}

void braid_generate_skey(unsigned char *skey)
{
	unsigned int i;
	for(i = 0; i < SKEY_SIZE; i++)
		skey[i] = _braid_prng_range(0x00, 0xff);
}

void braid_ckey_generate(braid_ckey_t *ckey, braid_t *priv, braid_t *K)
{
	braid_t *tmp = braid_alloc(K->length);

	//Set K and private key.
	ckey->K = K;
	ckey->priv = priv;

	//Allocate and calculate private inverse.
	//privr = priv^{-1}
	ckey->privr = braid_alloc(K->length);
	braid_inverse(ckey->privr, ckey->priv);

	//Allocate and calculate public key.
	//pub = priv*K*privr
	ckey->pub = braid_alloc(K->length);
	braid_combine(tmp, K, ckey->privr);
	braid_combine(ckey->pub, ckey->priv, tmp);

	braid_free(tmp);
}

void braid_ckey_generate_new(braid_ckey_t *ckey, braid_t *K)
{
	braid_t *tmp = braid_alloc(K->length);

	//Set K.
	ckey->K = K;

	//Allocate and shuffle private key.
	ckey->priv = BRAID_INIT(K->length);
	braid_shuffle(ckey->priv, 0, K->length / 2);

	//Allocate and calculate private inverse.
	//privr = priv^{-1}
	ckey->privr = braid_alloc(K->length);
	braid_inverse(ckey->privr, ckey->priv);

	//Allocate and calculate public key.
	//pub = priv*K*privr
	ckey->pub = braid_alloc(K->length);
	braid_combine(tmp, K, ckey->privr);
	braid_combine(ckey->pub, ckey->priv, tmp);

	braid_free(tmp);
}

void braid_encrypt_skey(braid_eskey_t *eskey, unsigned char *skey, braid_ckey_t *ckey)
{
	unsigned int i;
	braid_t *tmp1 = braid_alloc(ckey->K->length);
	braid_t *tmp2 = braid_alloc(ckey->K->length);

	//Generate random braid r.
	braid_t *r = BRAID_INIT(ckey->K->length);
	braid_shuffle(r, ckey->K->length / 2, 0);

	//Calculate random inverse.
	braid_t *rr = braid_alloc(ckey->K->length);
	braid_inverse(rr, r);

	//Calculate first part of ciphertext.
	//a = r*K*r^{-1}
	braid_t *a = braid_alloc(ckey->K->length);
	braid_combine(tmp1, ckey->K, rr);
	braid_combine(a, r, tmp1);
	eskey->a = a;

	//Calulate second part of ciphertext.
	braid_combine(tmp2, ckey->pub, rr);
	braid_combine(tmp1, r, tmp2);

	//Generate hash from tmp braid.
	sha2_context sha_ctx;
	sha2_starts(&sha_ctx, 0);
	for(i = 0; i < ckey->K->length; i++)
		sha2_update(&sha_ctx, (const unsigned char *)&(_charset[tmp1->items[i] % CHARSET_LENGTH]), 1);
	unsigned char digest[SKEY_SIZE];
	sha2_finish(&sha_ctx, digest);

	//Xor symmetric key with hash digest.
	//b = skey XOR H(r*pub*r^{-1})
	_braid_xor_skey(eskey->b, skey, digest, SKEY_SIZE);

	braid_free(tmp1);
	braid_free(tmp2);
}

void braid_decrypt_skey(unsigned char *skey, braid_eskey_t *eskey, braid_ckey_t *ckey)
{
	unsigned int i;
	braid_t *tmp1 = braid_alloc(ckey->K->length);
	braid_t *tmp2 = braid_alloc(ckey->K->length);

	//Calculate tmp braid.
	braid_combine(tmp2, eskey->a, ckey->privr);
	braid_combine(tmp1, ckey->priv, tmp2);

	//Generate hash from tmp braid.
	sha2_context sha_ctx;
	sha2_starts(&sha_ctx, 0);
	for(i = 0; i < ckey->K->length; i++)
		sha2_update(&sha_ctx, (const unsigned char *)&(_charset[tmp1->items[i] % CHARSET_LENGTH]), 1);
	unsigned char digest[SKEY_SIZE];
	sha2_finish(&sha_ctx, digest);

	//Xor encrypted symmetric key with hash digest.
	//skey = b XOR H(priv*a*priv^{-1})
	_braid_xor_skey(skey, eskey->b, digest, SKEY_SIZE);

	braid_free(tmp1);
	braid_free(tmp2);
}
