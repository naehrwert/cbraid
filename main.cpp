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

#include <stdio.h>
#include <stdlib.h>

#include "braid.h"

void print_braid(char *name, braid_t *b)
{
	printf("%s: ", name);
	braid_print(stdout, b);
	printf("\n");
}

void print_skey(char *name, unsigned char *skey)
{
	unsigned int i;
	printf("%s: ", name);
	for(i = 0; i < SKEY_SIZE; i++)
		printf("%02X", skey[i]);
	printf("\n");
}

void main()
{
	__braid_lib_init();
	atexit(__braid_lib_end);

	//Generate random public K.
	braid_t *K = braid_shuffle(BRAID_INIT(32), 0, 32);
	print_braid("K    ", K);
	printf("\n");
	
	//Generate new braid crypto key.
	braid_ckey_t *ckey = braid_ckey_alloc();
	braid_ckey_generate_new(ckey, K);

	FILE *fp = fopen("priv", "wb");
	braid_ckey_write_priv(fp, ckey);
	fclose(fp);
	fp = fopen("pub", "wb");
	braid_ckey_write_pub(fp, ckey);
	fclose(fp);

	printf("crypto key:\n");
	print_braid("priv ", ckey->priv);
	print_braid("privr", ckey->privr);
	print_braid("pub  ", ckey->pub);
	printf("\n");

	//Generate random secret key.
	unsigned char skey[SKEY_SIZE];
	braid_generate_skey(skey);
	printf("random secret key:\n");
	print_skey("skey ", skey);
	printf("\n");
	
	//Encrypt plaintext with secret key.
	//...

	//Encrypt secret key.
	braid_eskey_t eskey;
	braid_encrypt_skey(&eskey, skey, ckey);

	printf("encrypted secret key:\n");
	print_braid("a    ", eskey.a);
	print_skey("b    ", eskey.b);
	printf("\n");

	//Send ciphertext and encrypted secret key to destination.
	//...

	//Decrypt secret key.
	unsigned char d[SKEY_SIZE];
	braid_decrypt_skey(d, &eskey, ckey);
	printf("decrypted secret key:\n");
	print_skey("d    ", d);

	//Decrypt ciphertext.
	//...

	getchar();
}
