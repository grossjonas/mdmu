/*
 * =====================================================================================
 *
 *       Filename:  iso14443a-crc.cli
 *
 *    Description:  a small tool to get an iso14443a crc on the command line
 *
 *        Version:  1.0
 *        Created:  22.03.2011 18:59:44
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Jonas Groß 
 *        Company:  
 *
 *      Thanks to:
 *      			volker.zeihs@googlemail.com
 *      			martin
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include <nfc/nfc.h>

int
main(int argc, char *argv[]){

	bool bDebug = false;
	//bool bDebug = true;
	size_t szLen = 0;
	bool bOdd = false;

	if(argc == 1){
		printf("\nUSAGE: crc <hex-val> [-d]\n");
		return EXIT_FAILURE;
	}

	if(argc == 3){
		if(0 == strcmp(argv[2], "-d")){
			bDebug = true;
		}else{
			printf("\nUSAGE: crc <hex-value> [-d]\n");
			return EXIT_FAILURE;
		}
	}

	szLen = strlen(argv[1]);
	if(1 == (szLen%2)){
		printf("\nUSAGE: crc <hex-value> [-d] - hex value needs all nibbles(even the zero ones)");
		return EXIT_FAILURE;
	}

	char charTmp[szLen];
	strcpy(charTmp, argv[1]);
	byte_t btAr[szLen/2+2];

	size_t ic = 2;
	size_t ib = 0;
	while(ic<szLen+2){
		char cTmp[3];
		cTmp[0] = charTmp[ic-2];
		cTmp[1] = charTmp[ic-1];
		cTmp[2] = '\0';

		btAr[ib] = (byte_t)strtol(cTmp, NULL, 16);

		ib++;
		ic=ic+2;
	}

	iso14443a_crc_append(btAr, szLen/2);

	if(bDebug){
		if(argc == 2){
			printf("\n argv[2]:");
			printf("\n  %s", argv[2]);
		}
		printf("\n");

		printf("\n argv[1]: ");
		for(size_t i = 0; i < strlen(argv[1]); i++){
			printf("\n  hex: %02x char: %c", argv[1][i], argv[1][i]);
		}
		printf("\n");

		printf("\n btAr: ");
		for(size_t i = 0; i < sizeof(btAr); i++){
			printf("\n  hex: %02x dez: %d", btAr[i], btAr[i]);
		}
		printf("\n\nCRC: ");
	}

	printf("\n%02x%02x\n", btAr[sizeof(btAr)-2], btAr[sizeof(btAr)-1]);

	return EXIT_SUCCESS;
}


