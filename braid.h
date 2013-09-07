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

//See http://arxiv.org/abs/0711.3941 for mathematical background and used scheme.

#ifndef _BRAID_H_
#define _BRAID_H_

#include "sha2.h"

/*! Symmetric key size. */
#define SKEY_SIZE 32

/*! Allocate identity braid. */
#define BRAID_INIT(size) braid_identity(braid_alloc(size))

/*! Braid structure. */
typedef struct _braid_t
{
	/*! Length. */
	unsigned int length;
	/*! Items. */
	unsigned char *items;
} braid_t;

/*! Braid crypto key. */
typedef struct _braid_ckey_t
{
	/*! Public braid K. */
	braid_t *K;
	/*! Private braid. */
	braid_t *priv;
	/*! Private braid inverse. */
	braid_t *privr;
	/*! Public braid. */
	braid_t *pub;
} braid_ckey_t;

/*! Braid encrypted symmetric key. */
typedef struct _braid_eskey_t
{
	/*! First part of the encrypted symmetric key. */
	braid_t *a;
	/*! Second part of the encrypted symmetric key. */
	unsigned char b[SKEY_SIZE];
} braid_eskey_t;

/*!
* \brief Init braid lib.
*/
void __braid_lib_init();

/*!
* \brief End braid lib.
*/
void __braid_lib_end();

/*!
* \brief Allocate braid.
* \param length Braid length.
* \return NULL on error.
*/
braid_t *braid_alloc(unsigned int length);

/*!
* \brief Free braid.
* \param b The braid to free.
*/
void braid_free(braid_t *b);

/*!
* \brief Print braid in textform.
* \param fp File stream.
* \param b The braid to print.
*/
void braid_print(FILE *fp, braid_t *b);

/*!
* \brief Write braid to file.
* \param fp File stream.
* \param b The braid to write.
*/
void braid_write(FILE *fp, braid_t *b);

/*!
* \brief Read braid from file.
* \param fp File stream.
* \return NULL on error.
*/
braid_t *braid_read(FILE *fp);

/*!
* \brief Set braid to identity.
* \param b Input braid.
* \return Input braid.
*/
braid_t *braid_identity(braid_t *b);

/*!
* \brief Compare two braids element wise.
* \param b1 Input braid 1.
* \param b1 Input braid 2.
* \return Compare result.
*/
int braid_compare(braid_t *b1, braid_t *b2);

/*!
* \brief Shuffle braid.
* \param b Input braid.
* \param offset Shuffle starting index.
* \param size Shuffle length.
* \return Input braid.
*/
braid_t *braid_shuffle(braid_t *b, unsigned int offset, unsigned int size);

/*!
* \brief Compute the inverse of a braid.
* \param dst The braid that will hold the inverse.
* \param b Input braid.
* \return Inverse braid.
*/
braid_t *braid_inverse(braid_t *dst, braid_t *b);

/*!
* \brief Combine two braids.
* \param dst The braid that will hold the combination.
* \param b1 Input braid 1.
* \param b1 Input braid 2.
* \return Combined braid.
*/
braid_t *braid_combine(braid_t *dst, braid_t *b1, braid_t *b2);

/*!
* \brief Allocate crypto key.
* \return NULL on error.
*/
braid_ckey_t *braid_ckey_alloc();

/*!
* \brief Free crypto key.
* \param ckey Crypto key to free.
*/
void braid_ckey_free(braid_ckey_t *ckey);

/*!
* \brief Write the private key part.
* \param fp File stream.
* \param ckey Crypto key.
*/
void braid_ckey_write_priv(FILE *fp, braid_ckey_t *ckey);

/*!
* \brief Read the private key part and generate the public part.
* \param fp File stream.
* \param ckey Crypto key.
*/
void braid_ckey_read_priv(FILE *fp, braid_ckey_t *ckey);

/*!
* \brief Write the public key part.
* \param fp File stream.
* \param ckey Crypto key.
*/
void braid_ckey_write_pub(FILE *fp, braid_ckey_t *ckey);

/*!
* \brief Read the public key part.
* \param fp File stream.
* \param ckey Crypto key.
*/
void braid_ckey_read_pub(FILE *fp, braid_ckey_t *ckey);

/*!
* \brief Generate a crypto key from the private key part.
* \param ckey Crypto key.
* \param priv Private braid.
* \param K Public K braid.
*/
void braid_ckey_generate(braid_ckey_t *ckey, braid_t *priv, braid_t *K);

/*!
* \brief Generate a new crypto key.
* \param ckey Crypto key.
* \param K Public K braid.
*/
void braid_ckey_generate_new(braid_ckey_t *ckey, braid_t *K);

/*!
* \brief Generate a symmetric key.
* \param skey Secret key.
*/
void braid_generate_skey(unsigned char *skey);

/*!
* \brief Encrypt the symmetric key.
* \param eskey Encrypted secret key.
* \param skey Secret key.
* \param ckey Crypto key.
*/
void braid_encrypt_skey(braid_eskey_t *eskey, unsigned char *skey, braid_ckey_t *ckey);

/*!
* \brief Decrypt the symmetric key.
* \param skey Secret key.
* \param eskey Encrypted secret key.
* \param ckey Crypto key.
*/
void braid_decrypt_skey(unsigned char *skey, braid_eskey_t *eskey, braid_ckey_t *ckey);

#endif
