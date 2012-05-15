/*
 * =====================================================================================
 *
 *       Filename:  rfidungeon.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  07.01.2011 21:58:27
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Jonas Groß (jg), _
 *        Company:  _
 *
 * =====================================================================================
 */

/*

NIY:
mifare_desfire_set_ats, 

 */

/*-
 * Copyright (C) 2010, Romain Tartiere.
 * 
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 * 
 * $Id: mifare-desfire-info.c 692 2010-12-15 12:51:05Z rtartiere@il4p.fr $
 */

#include <err.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>

#include <readline/readline.h>
#include <readline/history.h>

#include <nfc/nfc.h>

#include <freefare.h> 

//----------------------------------------------------------------------------- helper functions

int 
readLong(long *lVal, char *str){
    int iRet = 0;
    long lTmp = 0;
    char *sEnd;
    char *sTmp;
    sTmp = readline(str);

    lTmp = strtol(sTmp, &sEnd, 10);

    if(sEnd == sTmp || errno == ERANGE)
	iRet = -1;
    else
	iRet = 1;

    *lVal = lTmp;

    return iRet;
}

int 
readUint8(uint8_t *i8, char *str){
    int iRet = 0;
    long lTmp = 0;
    uint8_t i8Tmp = 0;

    iRet = readLong(&lTmp, str);
    if(iRet < 0 | lTmp < 0 | lTmp>255){		
	iRet = -1;
    }else{
	i8Tmp = (uint8_t)lTmp;
    }
    *i8 = i8Tmp;

    return iRet;
}

int 
askCommunicationSettings(uint8_t *cs){
    int iRet = 0;
    long lSel = 0;
    long lTmp = 0; bool bLoop = true;
    int iCS = 0;
    while(bLoop){
	printf("\n Select Communication Mode: ");
	printf("\n [0] Plain");
	printf("\n [1] MACed");
	printf("\n [2] Enciphered");
	iRet = readLong(&lSel, "\n Please select an option: ");
	switch(lSel){
	    case(0):
		iCS = MDCM_PLAIN;
		bLoop = false;
		break;
	    case(1):
		iCS = MDCM_MACED;
		bLoop = false;
		break;
	    case(2):
		iCS = MDCM_ENCIPHERED;
		bLoop = false;
		break;
	    default:
		iCS = MDCM_PLAIN;
		printf("\n Unsupported -> Set to plain communication for compatibility");
		printf("\n Select other mode? ");
		printf("\n [0]N0 ");
		printf("\n [everything else] Yes");
		iRet = readLong(&lTmp, "\n Please select an option: ");
		if(lTmp == 0){
		    bLoop = false;
		    return -1;
		}
	}
    }
    *cs = (uint8_t)iCS;
    return iRet;
}

int 
askCS(int *cs){
    int iRet = 0;
    long lSel = 0;
    long lTmp = 0; bool bLoop = true;
    int iCS = 0;
    while(bLoop){
	printf("\n Select Communication Mode: ");
	printf("\n [0] Plain");
	printf("\n [1] MACed");
	printf("\n [2] Enciphered");
	iRet = readLong(&lSel, "\n Please select an option: ");
	switch(lSel){
	    case(0):
		iCS = MDCM_PLAIN;
		bLoop = false;
		break;
	    case(1):
		iCS = MDCM_MACED;
		bLoop = false;
		break;
	    case(2):
		iCS = MDCM_ENCIPHERED;
		bLoop = false;
		break;
	    default:
		iCS = MDCM_PLAIN;
		printf("\n Unsupported -> Set to plain communication for compatibility");
		printf("\n Select other mode? ");
		printf("\n [0]N0 ");
		printf("\n [everything else] Yes");
		iRet = readLong(&lTmp, "\n Please select an option: ");
		if(lTmp == 0){
		    bLoop = false;
		    return -1;
		}
	}
    }
    *cs = (uint8_t)iCS;
    return iRet;
}

int 
askAccessRights(uint16_t *access_rights){
    int iRet = 0;
    long lTmp = 0;

    uint16_t ar = 0;

    long lRead = 0;
    long lWrite = 0;
    long lReadWrite = 0;
    long lChange = 0;
    char strTmp[4];

    printf("\n Max number of possible keys is 13. ");
    printf("\n 14 means free access. ");
    printf("\n 15 means no access. ");

    iRet = readLong( &lRead, "\n Please enter the number of the key you want to use for read access: ");
    if(lRead < 0 || lRead > 15){
	printf("\n Input out of range - returning\n");
	return EXIT_FAILURE;
    }

    iRet = readLong( &lWrite, "\n Please enter the number of the key you want to use for write access: ");
    if(lWrite < 0 || lWrite > 15){
	printf("\n Input out of range - returning\n");
	return EXIT_FAILURE;
    }

    iRet = readLong( &lReadWrite, "\n Please enter the number of the key you want to use for read and write access: ");
    if(lReadWrite < 0 || lReadWrite > 15){
	printf("\n Input out of range - returning\n");
	return EXIT_FAILURE;
    }

    iRet = readLong( &lChange, "\n Please enter the number of the key you want to use for changing the access rights: ");
    if(lChange < 0 || lChange > 15){
	printf("\n Input out of range - returning\n");
	return EXIT_FAILURE;
    }

    sprintf(strTmp, "%lx%lx%lx%lx", lRead, lWrite, lReadWrite, lChange);

    //	printf("\n %s \n", strTmp);

    lTmp = strtol(strTmp, NULL, 16);

    //	printf("\n %lx %ld", lTmp, lTmp);

    ar = (uint16_t)lTmp;
    *access_rights = ar;

    return iRet;
}

int 
askFileNo(uint8_t *files[], size_t count, uint8_t *file_no){
	int iRet = 0;
	bool bLoop = true;
	long lTmp = 0;
	uint8_t fn = 0;

	while(bLoop){
		iRet =  readLong(&lTmp, "\n Please type a unallocated file number(28 max): ");
		if((lTmp > 28) || (lTmp < 0)){
			bLoop = true;
			printf("\n File number out of range");
			printf("\n Try again?");
			printf("\n [0] N0");
			printf("\n [everything else] Yes");
			iRet = readLong(&lTmp, "\n Please select an option: ");
			if(lTmp == 0){
				bLoop = false;
				return -1;
			}else{
				continue;
			}
		}else{
			bLoop = false;		
			for(int i=0; i<count; i++){
				if(files[i] == file_no){
					bLoop = true;
					printf("\n File number already allocated");
					printf("\n Try again?");
					printf("\n [0] N0");
					printf("\n [everything else] Yes");

					iRet = readLong(&lTmp, "\n Please select an option: ");
					if(lTmp == 0){
						bLoop = false;
						return -1;
					}else{
						bLoop = true;
						continue;
					}
				}
			}			
		}
	}

	*file_no = (uint8_t)lTmp;
	return iRet;
}

int
askKey(MifareDESFireKey *mdfk){
    int iRet = 0;	
    int iKeyLen = 0;
    long lTmp = 0;
    char *strTmp;
    char strTxt[15];
    uint8_t key_no = 0;
    uint8_t *abtKey;
    MifareDESFireKey key;

    printf("\n Select your key type: ");
    printf("\n [0] des");
    printf("\n [1] 3des");
    printf("\n [2] 3k3des");
    printf("\n [3] aes");
    iRet = readLong(&lTmp, "\n Please select an option: ");
    switch(lTmp){
	case(0):
	    iKeyLen = 8;
	    break;
	case(1):
	    iKeyLen = 16;
	    break;
	case(2):
	    iKeyLen = 24;
	    break;
	case(3):
	    iKeyLen = 16;
	    break;
	default:
	    printf("\n Input failure");
	    return -1;
    }

    abtKey = (uint8_t*)malloc(sizeof(uint8_t)*iKeyLen);

    sprintf(strTxt," Key(%d Byte): ", iKeyLen);
    strTmp = readline(strTxt);
    for(int i = 0; i<iKeyLen; i++){				
	abtKey[i] = (uint8_t)strtol(&strTmp[i], NULL, 10);
    }

    switch(lTmp){
	case(0):						
	    key = mifare_desfire_des_key_new (abtKey);
	    break;				
	case(1):
	    key = mifare_desfire_3des_key_new (abtKey);
	    break;
	case(2):
	    key = mifare_desfire_3k3des_key_new (abtKey);
	    break;
	case(3):
	    key = mifare_desfire_aes_key_new (abtKey);
	    break;
	    //default:
	    //You should never get here
    }
    free(abtKey);

    *mdfk = key;

    return iRet;
}

int 
askSettings(uint8_t *settings){
    int iRet = 0;
    long lSel = 0;
    uint8_t set = 0;

    bool bConfigChange = false;
    bool bCreateDelete = false;
    bool bListDirs = false;
    bool bChangeKey = false;

    printf("\n Configuration changeable? ");
    printf("\n [0] No");
    printf("\n [everything else] Yes");
    iRet = readLong(&lSel, "\n Please select an option: ");
    if(lSel != 0)	
        bConfigChange = true;

    printf("\n Master Key not required for create / delete? ");
    printf("\n [0] No");
    printf("\n [everything else] Yes");
    iRet = readLong(&lSel, "\n Please select an option: ");
    if(lSel != 0)
        bCreateDelete = true;

    printf("\n Free directory list access without Master Key? ");
    printf("\n [0] No");
    printf("\n [everything else] Yes");
    iRet = readLong(&lSel, "\n Please select an option: ");
    if(lSel != 0)
        bListDirs = true;

    printf("\n Allow changing the Master Key? ");
    printf("\n [0] No");
    printf("\n [everything else] Yes");
    iRet = readLong(&lSel, "\n Please select an option: ");
    if(lSel != 0)
        bChangeKey = true;

    if(bConfigChange) set |= 8;// Sets Bit 8 to 1
    if(bCreateDelete) set |= 4;
    if(bListDirs)	set |= 2;
    if(bChangeKey)	set |= 1;

    *settings = set;

    return iRet;
}

int
printLastPiccError(MifareTag tag){
    int iRet = 0;
    uint8_t error = 0;

    error = mifare_desfire_last_picc_error(tag);

    switch(error){
	case OPERATION_OK:
	    printf("OPERATION_OK");
	    break;
	case NO_CHANGES:
	    printf("NO_CHANGES");
	    break;
	case OUT_OF_EEPROM_ERROR:
	    printf("OUT_OF_EEPROM_ERROR");
	    break;
	case ILLEGAL_COMMAND_CODE:
	    printf("ILLEGAL_COMMAND_CODE");
	    break;
	case INTEGRITY_ERROR:
	    printf("INTEGRITY_ERROR");
	    break;
	case NO_SUCH_KEY:
	    printf("NO_SUCH_KEY");
	    break;
	case LENGTH_ERROR:
	    printf("LENGTH_ERROR");
	    break;
	case PERMISSION_ERROR:
	    printf("PERMISSION_ERROR");
	    break;
	case PARAMETER_ERROR:
	    printf("PARAMETER_ERROR");
	    break;
	case APPLICATION_NOT_FOUND:
	    printf("APPLICATION_NOT_FOUND");
	    break;
	case APPL_INTEGRITY_ERROR:
	    printf("APPL_INTEGRITY_ERROR");
	    break;
	case AUTHENTICATION_ERROR:
	    printf("AUTHENTICATION_ERROR");
	    break;
	case ADDITIONAL_FRAME:
	    printf("ADDITIONAL_FRAME");
	    break;
	case BOUNDARY_ERROR:
	    printf("BOUNDARY_ERROR");
	    break;
	case PICC_INTEGRITY_ERROR:
	    printf("PICC_INTEGRITY_ERROR");
	    break;
	case COMMAND_ABORTED:
	    printf("COMMAND_ABORTED");
	    break;
	case PICC_DISABLED_ERROR:
	    printf("PICC_DISABLED_ERROR");
	    break;
	case COUNT_ERROR:
	    printf("COUNT_ERROR");
	    break;
	case DUPLICATE_ERROR:
	    printf("DUPLICATE_ERROR");
	    break;
	case EEPROM_ERROR:
	    printf("EEPROM_ERROR");
	    break;
	case FILE_NOT_FOUND:
	    printf("FILE_NOT_FOUND");
	    break;
	case FILE_INTEGRITY_ERROR:
	    printf("FILE_INTEGRITY_ERROR");
	    break;
	default:
	    printf("Unknown error: %d", error);
    }

    return iRet;
}

//----------------------------------------------------------------------------- additional gui functions 
int
printApplicationIDs(MifareTag tag){
	int ret = EXIT_SUCCESS;
	MifareDESFireAID *aids = NULL;
	size_t aid_count;

	printf("\n");

	ret = mifare_desfire_get_application_ids (tag, &aids, &aid_count);
	printf("\n Number of installed Applications: %zu", aid_count);    

	for(int i=0; i<aid_count; i++){
		printf("\n    [%d] %02x ", i, mifare_desfire_aid_get_aid(aids[i]));
	}

	mifare_desfire_free_application_ids (aids);

	printf("\n");
	return ret;
}

int 
printAccessRights(MifareTag tag, uint8_t fn){
    int iRet = 0;
    long lTmp = 0;

    struct mifare_desfire_file_settings set;
    char strHex[4];

    char strRead[2];
    char strWrite[2];
    char strReadWrite[2];
    char strChange[2];

    strRead[1] = '\0';
    strWrite[1] = '\0';
    strReadWrite[1] = '\0';
    strChange[1] = '\0';

    iRet = mifare_desfire_get_file_settings(tag, fn, &set);
    if(iRet < 0){
	warnx(" Getting file settings failed ");
	iRet = printLastPiccError(tag);
	return EXIT_FAILURE;
    }

    sprintf(strHex, "%02x", set.access_rights);

    strncpy(strRead, strHex, 1);
    strncpy(strWrite, strHex + 1, 1);
    strncpy(strReadWrite, strHex + 2, 1);
    strncpy(strChange, strHex + 3, 1);

    printf("\n Key needed for:");

    lTmp = strtol(strRead, NULL, 16);
    printf("\n Read: ");
    if(lTmp == 14)
	printf("none(free access)");
    else if(lTmp == 15)
	printf("access denied");
    else
	printf("%ld", lTmp);

    lTmp = strtol(strWrite, NULL, 16);
    printf("\n Write: ");
    if(lTmp == 14)
	printf("none(free access)");
    else if(lTmp == 15)
	printf("access denied");
    else
	printf("%ld", lTmp);

    lTmp = strtol(strReadWrite, NULL, 16);
    printf("\n Read and write: ");
    if(lTmp == 14)
	printf("none(free access)");
    else if(lTmp == 15)
	printf("access denied");
    else
	printf("%ld", lTmp);

    lTmp = strtol(strChange, NULL, 16);
    printf("\n Change: ");
    if(lTmp == 14)
	printf("none(free access)");
    else if(lTmp == 15)
	printf("access denied");
    else
	printf("%ld", lTmp);

    printf("\n");
    return iRet;
}

int 
printVersionKeySettings(MifareTag tag){	  
    int ret = EXIT_SUCCESS; 
    uint8_t settings;
    uint8_t max_keys;
    struct mifare_desfire_version_info info;

    printf("\n");

    char *tagUid = freefare_get_tag_uid (tag);
    printf ("===> Version information for tag %s:\n", tagUid);

    ret = mifare_desfire_get_version (tag, &info);
    if (ret < 0) {
	freefare_perror (tag, "mifare_desfire_get_version");
	return ret;
    }

    printf ("UID:                      0x%02x%02x%02x%02x%02x%02x%02x\n", info.uid[0], info.uid[1], info.uid[2], info.uid[3], info.uid[4], info.uid[5], info.uid[6]);
    printf ("Batch number:             0x%02x%02x%02x%02x%02x\n", info.batch_number[0], info.batch_number[1], info.batch_number[2], info.batch_number[3], info.batch_number[4]);
    printf ("Production date:          week %x, 20%02x\n", info.production_week, info.production_year);
    printf ("Hardware Information:\n");
    printf ("    Vendor ID:            0x%02x\n", info.hardware.vendor_id);
    printf ("    Type:                 0x%02x\n", info.hardware.type);
    printf ("    Subtype:              0x%02x\n", info.hardware.subtype);
    printf ("    Version:              %d.%d\n", info.hardware.version_major, info.hardware.version_minor);
    printf ("    Storage size:         0x%02x (%s%d bytes)\n", info.hardware.storage_size, (info.hardware.storage_size & 1) ? ">" : "=", (int)pow (2, info.hardware.storage_size >> 1));
    printf ("    Protocol:             0x%02x\n", info.hardware.protocol);
    printf ("Software Information:\n");
    printf ("    Vendor ID:            0x%02x\n", info.software.vendor_id);
    printf ("    Type:                 0x%02x\n", info.software.type);
    printf ("    Subtype:              0x%02x\n", info.software.subtype);
    printf ("    Version:              %d.%d\n", info.software.version_major, info.software.version_minor);
    printf ("    Storage size:         0x%02x (%s%d bytes)\n", info.software.storage_size, (info.software.storage_size & 1) ? ">" : "=", (int)pow (2, info.software.storage_size >> 1));
    printf ("    Protocol:             0x%02x\n", info.software.protocol);

    ret = mifare_desfire_get_key_settings (tag, &settings, &max_keys);
    if (ret < 0) {
	freefare_perror (tag, "mifare_desfire_get_key_settings");
	return ret;
    }

    printf ("Master Key settings (0x%02x):\n", settings);
    printf ("    0x%02x configuration changeable;\n", settings & 0x08);
    printf ("    0x%02x PICC Master Key not required for create / delete;\n", settings & 0x04);
    printf ("    0x%02x Free directory list access without PICC Master Key;\n", settings & 0x02);
    printf ("    0x%02x Allow changing the Master Key;\n", settings & 0x01);

    printf("\n");
    return ret;
}

int
printDevice(nfc_device_t *device){
    int iRet = 1;

    printf("\n Device data:");
    printf("\n Initialized successful: ");
/*
	if(device->bActive)
	printf(" OK ");
    else
	printf(" Fail ");
*/
    printf("\n Supports 14443-4: ");
    if(device->bAutoIso14443_4)
	printf(" OK ");
    else
	printf(" Fail ");

    printf("\n Supports CRC-adding: ");
    if(device->bCrc)
	printf(" OK ");
    else
	printf(" Fail ");

    printf("\n");

    return iRet;
}

//----------------------------------------------------------------------------- libnfc/nfc-tools functions

int 
setAts(MifareTag tag){
	int iRet = 0;
	uint8_t *ats; 
	long lTmp = 0;
	uint8_t btT0 = 0;
	uint8_t btTA = 0;
	uint8_t btTB = 0;
	uint8_t btTC = 0;
	uint8_t *abtHistorical;
// Format ats:
// TL -> T0 -> TA -> TB -> TC -> Historical bytes (x Byte) -> CRC (2 Byte)
// TL : 5.2.2 Length Byte
// TL = sizeof(ats) - 2 Bytes
// TL < FSD - 2 => ???
// The FSD defines the maximum size of a frame the PCD is able to receive
// Max FSD -> libnfc/examples/nfc-utils.c : 
// const int iMaxFrameSizes[] = { 16, 24, 32, 40, 48, 64, 96, 128, 256 };
// printf ("* Max Frame Size accepted by PICC: %d bytes\n", iMaxFrameSizes[nai.abtAts[0] & 0x0F]);
// --> iMaxFramseSizes = possible maximal FSD
// --> possible Ats[0]  -> 0xX + 0...8 -> iMaxFrameSizes[].length = 9 
//
// TO: 5.2.3 Format Byte
	uint8_t btFB = 0;
//	inverse to libnfc/examples/nfc-utils.c:207-231
	printf("\n ATS:");

//TA Settings
	printf("\n Set bit rate capability");
	printf("\n Support only 106 kbits/s in both directions?");
	printf("\n [0] N0");
	printf("\n [1] Yes");
    iRet = readLong(&lTmp, "\n Please select an option: ");
    if(lTmp == 1){
		// btTA == 0 -> alles cool
	}else{
		printf("\n Set same bit rate in both directions (PICC2PCD && PCD2PICC)?"); 
		printf("\n [0] N0");
		printf("\n [1] Yes");
   		iRet = readLong(&lTmp, "\n Please select an option: ");
    	if(lTmp == 1){
			//ToDo: Set Bit 7
			btTA = btTA | 1 << 7; 
		}else{
		}

		printf("\n PICC -> PCD: Set bitrate to 212 kbits/s (DS=2)?"); 
		printf("\n [0] N0");
		printf("\n [1] Yes");
   		iRet = readLong(&lTmp, "\n Please select an option: ");
    	if(lTmp == 1){
			//ToDo: Set Bit 4
			btTA = btTA | 1 << 4; 
		}else{
		printf("\n [0] N0");
		printf("\n [1] Yes");
   		iRet = readLong(&lTmp, "\n Please select an option: ");
    	if(lTmp == 1){
			//ToDo: Set Bit 5
			btTA = btTA | 1 << 5; 
		}else{
		}
		printf("\n PICC -> PCD: Set bitrate to 847 kbits/s (DS=8)?"); 
		printf("\n [0] N0");
		printf("\n [1] Yes");
   		iRet = readLong(&lTmp, "\n Please select an option: ");
    	if(lTmp == 1){
			//ToDo: Set Bit 6
			btTA = btTA | 1 << 6; 
		}else{
		}
		printf("\n PCD -> PICC: Set bitrate to 212 kbits/s (DR=2)?"); 
		printf("\n [0] N0");
		printf("\n [1] Yes");
   		iRet = readLong(&lTmp, "\n Please select an option: ");
    	if(lTmp == 1){
			//ToDo: Set Bit 0
			btTA = btTA | 1 << 0; 
		}else{
		}
		printf("\n PCD -> PICC: Set bitrate to 424 kbits/s (DR=4)?"); 
		printf("\n [0] N0");
		printf("\n [1] Yes");
   		iRet = readLong(&lTmp, "\n Please select an option: ");
    	if(lTmp == 1){
			//ToDo: Set Bit 1
			btTA = btTA | 1 << 1; 
		}else{
		}
		printf("\n PCD -> PICC: Set bitrate to 847 kbits/s (DR=8)?"); 
		printf("\n [0] N0");
		printf("\n [1] Yes");
   		iRet = readLong(&lTmp, "\n Please select an option: ");
    	if(lTmp == 1){
			//ToDo: Set Bit 2
			btTA = btTA | 1 << 2; 
		}else{
		}
	}
//TB Settings
	printf("\n Set frame waiting time and frame guard time?");
	printf("\n [0] N0");
	printf("\n [1] Yes");
    iRet = readLong(&lTmp, "\n Please select an option: ");
    if(lTmp == 1){
		printf("\n Set frame waiting time?");
		printf("\n [0] N0");
		printf("\n [1] Yes");
    	iRet = readLong(&lTmp, "\n Please select an option: ");
    	if(lTmp == 1){	
			bool bQuest = true;
			while(bQuest){
				//ToDo: Do insert code here
				//SFGI 0 ... 14 - waiting time
// 256.0*16.0*(1<<((TB & 0xf0) >> 4))/13560.0)
// -> SFGI = ((TB & 0f00) >> 4)
// -> 2^(SFGI) = 1<<SFGI

// (256 * 16 / fc ) * 2^(SFGI)

				

			}
		}
		printf("\n Set frame guard time?");
		printf("\n [0] N0");
		printf("\n [1] Yes");
    	iRet = readLong(&lTmp, "\n Please select an option: ");
    	if(lTmp == 1){	
			bool bQuest = true;
			while(bQuest){
				//ToDo: Do insert code here
				//SFGT 0 ... 14 - guard time

			}
		}
	}else{

	}

//TC Settings
	printf("\n Set Node ADdress and Card IDentifier support");
	printf("\n [0] N0");
	printf("\n [1] Yes");
    iRet = readLong(&lTmp, "\n Please select an option: ");
    if(lTmp == 1){
		printf("\n Suppport Node ADdress? ");
		printf("\n [0] N0");
		printf("\n [1] Yes");
    	iRet = readLong(&lTmp, "\n Please select an option: ");
    	if(lTmp == 1){
			//ToDo: Set Bit 1 of TC
			btTB = btTB | 1 << 1; 
		}else{
		}
		printf("\n Suppport Card IDentifier? ");
		printf("\n [0] N0");
		printf("\n [1] Yes");
    	iRet = readLong(&lTmp, "\n Please select an option: ");
    	if(lTmp == 1){
			//ToDo: Set Bit 2 of TC
			btTB = btTB | 1 << 2; 
		}else{
		}
	}else{
		//Do nothing
	}
//Historical Bytes
//ToDo: sudo implement_this


	printf("\n ToDo: here");
/*
    iRet = mifare_desfire_set_ats(tag, ats);
	if(iRet < 0){
	    warnx("Setting answer to select failed");
    	printLastPiccError(tag);
	}else{
        printf("\n Answer to select set successfully"); 
	}
*/
	return iRet;
}

int
setDefaultKey(MifareTag tag){
    int	iRet = 0;
    MifareDESFireKey key;

    iRet = askKey(&key);

    iRet = mifare_desfire_set_default_key(tag, key);
    if(iRet < 0){
	    warnx("Setting new default key failed");
    	printLastPiccError(tag);
    }else{
        printf("\n New default key set successfully"); 
    }    

    free(key);
    printf("\n");
    return iRet;
}

int 
setConfiguration(MifareTag tag){
    int iRet = 0;
    long lTmp = 0;
    bool enable_random_uid = false;
    bool disable_format = false;

    printf("\n ToDo: These options can only be applied to a ev1 Tag\n");

    printf("\n Do you want to disable formating this tag?");
    printf("\n [0]N0");
    printf("\n [everything else] Yes");
    iRet = readLong(&lTmp, "\n Please select an option: ");
    if(lTmp == 0){
        disable_format = false;
    }else{
        disable_format = true;
    }

    printf("\n Do you want to enable random uid?");
    printf("\n [0]N0");
    printf("\n [everything else] Yes");
    iRet = readLong(&lTmp, "\n Please select an option: ");
    if(lTmp == 0){
        enable_random_uid = false;
    }else{
        enable_random_uid = true;
    }

    iRet = mifare_desfire_set_configuration(tag, disable_format, enable_random_uid);
    if(iRet < 0){
        warnx("Setting configuration failed");
        printLastPiccError(tag);
    }else{
        printf("\n New configuration set successfully");
    }

    printf("\n");
    return iRet;
}

int
authenticate(MifareTag tag){
    int iRet = 0;
    bool bQuest = true;
    uint8_t key_no = 0;
    long lTmp = 0;
    MifareDESFireKey autKey;

    while(bQuest){
	printf("\n Select the key you want to use to authenticate(0-13): ");
	iRet = readUint8( &key_no, "");
	if((key_no < 0) || (key_no > 13)){
	    printf("\n Input error");
	    printf("\n Try again?");
	    printf("\n [0] N0");
	    printf("\n [everything else] Yes");

	    iRet = readLong(&lTmp, "\n Please select an option: ");
	    if(lTmp == 0){
		bQuest = false;
		break;
	    }else{
		continue;
	    }
	}else{
	    bQuest = false;
	}
    }

    iRet = askKey(&autKey);

    iRet = mifare_desfire_authenticate(tag, key_no, autKey);
    if(iRet<0){
	warnx(" Authentication Error");
	printLastPiccError(tag);
    }else{
	printf("\n Authenticated ");
    }

    free(autKey);
    printf("\n");
    return iRet;
}

int
changeKeySettings(MifareTag tag){
    bool bQuest = true;
    int iRet = 0;
    long lTmp = 0;
    long lSel = 0;
    uint8_t settings = 0;

    printf("\n");

    iRet = askSettings( &settings);

    iRet = mifare_desfire_change_key_settings(tag, settings);
    if(iRet < 0){
	warnx(" Changing key settings failed!");
	printLastPiccError(tag);
    }else{
	printf("\n Key changed successfully");
    }

    printf("\n");
    return iRet;
}

int
changeKey(MifareTag tag){ 
    int iRet = 0;
    int iKeyBytes = 0;
    long lTmp = 0;
    bool bQuest = true;
    char *strKey;
    char *strTmp;
    uint8_t key_no = 0;

    MifareDESFireKey mdfk_old;
    MifareDESFireKey mdfk_new;
    uint8_t version = 0;

    while(bQuest){
	iRet = readLong(&lTmp, "\n Please enter the number of the key( 0-13 ): ");
	if(iRet <= 0 || lTmp < 0 || lTmp > 13){
	    printf("\n Input not recognized - Try again?");
	    printf("\n [0] N0");
	    printf("\n [everything else] Yes");
	    iRet = readLong(&lTmp, "\n Please select an option: ");
	    if(lTmp == 0){
		bQuest = false;
		break;
	    }else{
		continue;
	    }

	}
	key_no = (uint8_t) lTmp;

	printf("\n Please enter old key data:");
	iRet = askKey(&mdfk_old);
	printf("\n Please enter desired key data:");
	iRet = askKey(&mdfk_new);

	printf("\n Do you want to set a version for the key: ");
	printf("\n [0] N0");
	printf("\n [everything else] Yes");
	iRet = readLong(&lTmp, "\n Please select an option: ");
	if(lTmp != 0){
	    iRet = readLong(&lTmp, "\n Please enter a version( 0-255 ): ");
	    if(iRet <= 0 || lTmp < 0 || lTmp > 255){
		printf("\n Input not recognized - Try again?");
		printf("\n [0] N0");
		printf("\n [everything else] Yes");
		iRet = readLong(&lTmp, "\n Please select an option: ");
		if(lTmp == 0){
		    bQuest = false;
		    break;
		}else{
		    continue;
		}

	    }
	    version = (uint8_t)lTmp;
	    mifare_desfire_key_set_version(mdfk_new, version);
	    printf("\n Version set");			
	}	

	iRet = mifare_desfire_change_key(tag, key_no, mdfk_new, mdfk_old);
	if(iRet < 0){
	    warnx("Changing key failed");
	    iRet = printLastPiccError(tag);
	}else{
	    printf("\n Key changed successfully");
	    bQuest = false;
	}
    }//while(bQuest)

    mifare_desfire_key_free (mdfk_old);
    mifare_desfire_key_free (mdfk_new);

    printf("\n");
    return iRet;
}

int 
changeFileSettings(MifareTag tag, uint8_t file_no){
    int iRet = 0;
    long lSel = 0;
    uint8_t communication_settings = 0;
    uint16_t access_rights = 0;
    int read = 1;
    int write = 1;
    int read_write = 1;
    int change_access_rights = 1;

    printf("\n Select Communication Mode: ");
    printf("\n [0] Plain");
    printf("\n [1] MACed");
    printf("\n [2] Enciphered");
    printf("\n ");
    iRet = readLong(&lSel, "");
    switch(lSel){
	case(0):
	    communication_settings = MDCM_PLAIN;
	    break;
	case(1):
	    communication_settings = MDCM_MACED;
	    break;
	case(2):
	    communication_settings = MDCM_ENCIPHERED;
	    break;
	default:
	    communication_settings = MDCM_PLAIN;
	    printf("Unsupported -> Set to plain communication for compatibility");
    }

    iRet = askAccessRights(&access_rights);

    iRet = mifare_desfire_change_file_settings(tag,file_no, communication_settings, access_rights);
    if(iRet < 0){
	warnx("Changing file settings failed");
	iRet = printLastPiccError(tag);
    }else{
	printf("\n File settings changed successfully");
    }

    printf("\n");
    return iRet;
}

int 
getValue(MifareTag tag, uint8_t file_no){
    int iRet = 0;
    int cs = 0;
    long lSel = 0;
    long lTmp = 0;
    bool bLoop = true;
    int32_t value = 0;
    iRet = mifare_desfire_get_value ( tag, file_no, &value);
    if(iRet < 0){
	warnx ("Getting value failed");
	iRet = printLastPiccError(tag);
	printf("\n You can try other communication settings");
	printf("\n [0] N0 ");
	printf("\n [everything else] Yes");
	iRet = readLong(&lTmp, "\n Please select an option: ");
	if(lTmp == 0){
	    return -1;
	}else{
	    while(bLoop){

		iRet = askCS(&cs);
		if(iRet < 0)
		    return EXIT_FAILURE;

		iRet = mifare_desfire_get_value_ex( tag,  file_no, &value, cs);
		if(iRet < 0){
		    warnx("Getting value with communication settings failed");
		    iRet = printLastPiccError(tag); 
		    printf("\n Try again");
		    printf("\n [0] N0 ");
		    printf("\n [everything else] Yes");
		    iRet = readLong(&lTmp, "\n Please select an option: ");
		    if(lTmp == 0){
			return -1;
		    }else{
			bLoop = true;
		    }
		}else{
		    bLoop = false;
		}
	    }//bLoop
	}
    }
    printf("\n value: %d", value);
    printf("\n");
    return iRet;
}

int 
credit(MifareTag tag, uint8_t file_no){
    int iRet = 0;
    int cs = 0;
    long lSel = 0;
    long lTmp = 0;
    bool bLoop = true;
    bool bQuest = true;
    int32_t amount = 0;

    while(bQuest){
	iRet = readLong(&lTmp, "Please enter the credit amount: ");
	if(iRet < 0 || lTmp < 0 || lTmp > UINT32_MAX){
	    warnx("Input failure");
	    printf("\n Try again?");
	    printf("\n [0] N0 ");
	    printf("\n [everything else] Yes");
	    iRet = readLong(&lTmp, "\n Please select an option: ");
	    if(lTmp == 0){
		bQuest = false;
		return -1;
	    }
	}else{
	    amount = (uint8_t)lTmp;
	    bQuest = false;
	}	
    }

    iRet = mifare_desfire_credit( tag, file_no, amount);
    if(iRet < 0){
	warnx ("Crediting value failed");
	iRet = printLastPiccError(tag);
	printf("\n You can try other communication settings");
	printf("\n [0] N0 ");
	printf("\n [everything else] Yes");
	iRet = readLong(&lTmp, "\n Please select an option: ");
	if(lTmp == 0){
	    return -1;
	}else{
	    while(bLoop){

		iRet = askCS(&cs);
		if(iRet < 0)
		    return EXIT_FAILURE;

		iRet = mifare_desfire_credit_ex( tag,  file_no, amount, cs);
		if(iRet < 0){
		    warnx("Crediting with communication settings failed");
		    iRet = printLastPiccError(tag);
		    printf("\n Try again");
		    printf("\n [0] N0 ");
		    printf("\n [everything else] Yes");
		    iRet = readLong(&lTmp, "\n Please select an option: ");
		    if(lTmp == 0){
			return -1;
		    }else{
			bLoop = true;
		    }
		}else{
		    bLoop = false;
		}
	    }//bLoop
	}
    }else{
	printf("\n Amount(%"PRIu8") credited successfully", amount);
    }

    printf("\n");
    return iRet;
}

int 
debit(MifareTag tag, uint8_t file_no){
    int iRet = 0;
    int cs = 0;
    long lSel = 0;
    long lTmp = 0;
    bool bLoop = true;
    bool bQuest = true;
    int32_t amount = 0;

    while(bQuest){
	iRet = readLong(&lTmp, "Please enter the debit amount: ");
	if(iRet < 0 || lTmp < 0 || lTmp > UINT32_MAX){
	    warnx("Input failure");
	    printf("\n Try again?");
	    printf("\n [0] N0 ");
	    printf("\n [everything else] Yes");
	    iRet = readLong(&lTmp, "\n Please select an option: ");
	    if(lTmp == 0){
		bQuest = false;
		return -1;
	    }
	}else{
	    amount = (uint8_t)lTmp;
	    bQuest = false;
	}	
    }

    iRet = mifare_desfire_debit( tag, file_no, amount);
    if(iRet < 0){
	warnx ("Debiting value failed");
	iRet =  printLastPiccError(tag);
	printf("\n You can try other communication settings");
	printf("\n [0] N0 ");
	printf("\n [everything else] Yes");
	iRet = readLong(&lTmp, "\n Please select an option: ");
	if(lTmp == 0){
	    return -1;
	}else{
	    while(bLoop){

		iRet = askCS(&cs);
		if(iRet < 0)
		    return EXIT_FAILURE;

		iRet = mifare_desfire_debit_ex( tag,  file_no, amount, cs);
		if(iRet < 0){
		    warnx("Debiting value with communication settings failed");
		    iRet = printLastPiccError(tag);
		    printf("\n Try again");
		    printf("\n [0] N0 ");
		    printf("\n [everything else] Yes");
		    iRet = readLong(&lTmp, "\n Please select an option: ");
		    if(lTmp == 0){
			return -1;
		    }else{
			bLoop = true;
		    }
		}else{
		    bLoop = false;
		}
	    }//bLoop
	}
    }else{
	printf("\n Amount(%"PRIu8") debited successfully", amount);
    }

    printf("\n");
    return iRet;	
}

int 
limitedCredit(MifareTag tag, uint8_t file_no){
    int iRet = 0;
    int cs = 0;
    long lSel = 0;
    long lTmp = 0;
    bool bLoop = true;
    bool bQuest = true;
    int32_t amount = 0;

    while(bQuest){
	iRet = readLong(&lTmp, "Please enter the amount to limit: ");
	if(iRet < 0 || lTmp < 0 || lTmp > UINT32_MAX){
	    warnx("Input failure");
	    printf("\n Try again?");
	    printf("\n [0] N0 ");
	    printf("\n [everything else] Yes");
	    iRet = readLong(&lTmp, "\n Please select an option: ");
	    if(lTmp == 0){
		bQuest = false;
		return -1;
	    }
	}else{
	    amount = (uint8_t)lTmp;
	    bQuest = false;
	}	
    }

    iRet = mifare_desfire_limited_credit( tag, file_no, amount);
    if(iRet < 0){
	warnx ("Crediting value failed");
	iRet = printLastPiccError(tag);
	printf("\n You can try other communication settings");
	printf("\n [0] N0 ");
	printf("\n [everything else] Yes");
	iRet = readLong(&lTmp, "\n Please select an option: ");
	if(lTmp == 0){
	    return -1;
	}else{
	    while(bLoop){

		iRet = askCS(&cs);
		if(iRet < 0)
		    return EXIT_FAILURE;

		iRet = mifare_desfire_limited_credit_ex( tag,  file_no, amount, cs);
		if(iRet < 0){
		    warnx("Crediting with communication settings failed");
		    iRet = printLastPiccError(tag);
		    printf("\n Try again");
		    printf("\n [0] N0 ");
		    printf("\n [everything else] Yes");
		    iRet = readLong(&lTmp, "\n Please select an option: ");
		    if(lTmp == 0){
			return -1;
		    }else{
			bLoop = true;
		    }
		}else{
		    bLoop = false;
		}
	    }//bLoop
	}
    }

    return iRet;	
}

int 
writeRecord(MifareTag tag, uint8_t file_no){
    int iRet = 0;
    int cs = 0;
    int iFileSize = 0;
    int iSize = 0;
    long lSel = 0;
    long lTmp = 0;
    bool bLoop = true;
    bool bQuest = true;
    off_t offset = 0;
    size_t length = 0;



    int iRecordSize = 0;
    int iMaxRecords = 0;
    int iCurrentRecords = 0;

    struct mifare_desfire_file_settings set;

    iRet = mifare_desfire_get_file_settings(tag, file_no, &set);
    iFileSize = set.settings.standard_file.file_size;
    iRecordSize = set.settings.linear_record_file.record_size;
    iMaxRecords = set.settings.linear_record_file.max_number_of_records;
    iCurrentRecords = set.settings.linear_record_file.current_number_of_records;


    printf("\n Selected file has space for %d records with a size of %d bytes per record. There currently are %d records.", iMaxRecords, iRecordSize, iCurrentRecords);

    while(bQuest){
	iRet = readLong(&lTmp, "\n Please select the record to start at: ");
	if(iRet < 0 || lTmp < 0 || lTmp > iMaxRecords){
	    warnx(" Input failure");
	    printf("\n Try again?");
	    printf("\n [0] N0 ");
	    printf("\n [everything else] Yes");
	    iRet = readLong(&lTmp, "\n Please select an option: ");
	    if(lTmp == 0){
		bQuest = false;
		return -1;
	    }
	}else{
	    offset = (off_t)lTmp;
	    bQuest = false;
	}	
    }

    bQuest = true;
    while(bQuest){
	iRet = readLong(&lTmp, "\n Please select how many records you want to use: ");

	if(iRet < 0 || lTmp < 0 || lTmp > (iMaxRecords - (int)offset)){
	    warnx("Input failure(Out of range?)");
	    printf("\n Try again?");
	    printf("\n [0] N0 ");
	    printf("\n [everything else] Yes");
	    iRet = readLong(&lTmp, "\n Please select an option: ");
	    if(lTmp == 0){
		bQuest = false;
		return -1;
	    }
	}else{
	    length = (size_t)lTmp;
	    bQuest = false;
	}	
	/*
	   length = (size_t)lTmp;
	   bQuest = false;*/
    }

    iSize = iFileSize*length;	

    char * strTmp;
    char strData[iSize];
    for(int i = 0; i < iSize; i++){
	strData[i] = '\0';
    }

    printf("\n Please enter the data(%d Byte): ", iSize);
    strTmp = readline("\n");

    if(strlen(strTmp) < iFileSize)
	iSize = strlen(strData);
    else
	iSize = iFileSize;

    memcpy(strData, strTmp, iSize);

    iRet = mifare_desfire_write_record( tag, file_no, offset, strlen(strData), &strData);
    if(iRet < 0){
	warnx (" Writing record failed");
	iRet = printLastPiccError(tag);
	printf("\n You can try other communication settings");
	printf("\n [0] N0 ");
	printf("\n [everything else] Yes");
	iRet = readLong(&lTmp, "\n Please select an option: ");
	if(lTmp == 0){
	    return -1;
	}else{
	    while(bLoop){

		iRet = askCS(&cs);
		if(iRet < 0)
		    return EXIT_FAILURE;

		iRet = mifare_desfire_write_record_ex( tag, file_no, offset, length, &strData, cs);
		if(iRet < 0){
		    warnx(" Writing record with communication settings failed");
		    iRet = printLastPiccError(tag);
		    printf("\n Try again");
		    printf("\n [0] N0 ");
		    printf("\n [everything else] Yes");
		    iRet = readLong(&lTmp, "\n Please select an option: ");
		    if(lTmp == 0){
			return -1;
		    }else{
			bLoop = true;
		    }
		}else{
		    bLoop = false;
		}
	    }//bLoop
	}
    }else{
	printf("\n Record(%d Bytes) successfully writen", iRet);
    }

    printf("\n");
    return iRet;
}

int 
readRecords(MifareTag tag, uint8_t file_no){
    int iRet = 0;
    int cs = 0;

    long lSel = 0;
    long lTmp = 0;
    bool bLoop = true;
    bool bQuest = true;
    off_t offset = 0;
    size_t length = 0;
    //void *data;
    //char *strData;
    int iRecordSize = 0;
    int iMaxRecords = 0;
    int iCurrentRecords = 0;
    struct mifare_desfire_file_settings set;

    iRet = mifare_desfire_get_file_settings(tag, file_no, &set);
    iRecordSize = set.settings.linear_record_file.record_size;
    iMaxRecords = set.settings.linear_record_file.max_number_of_records;
    iCurrentRecords = set.settings.linear_record_file.current_number_of_records;


    printf("\n Selected file has space for %d records with a size of %d bytes per record. There currently are %d records.", iMaxRecords, iRecordSize, iCurrentRecords);

    while(bQuest){
	iRet = readLong(&lTmp, " \n Please select a record to start with: ");
	if(iRet < 0 || lTmp < 0 || lTmp > iMaxRecords){
	    warnx("Input failure");
	    printf("\n Try again?");
	    printf("\n [0] N0 ");
	    printf("\n [everything else] Yes");
	    iRet = readLong(&lTmp, "\n Please select an option: ");
	    if(lTmp == 0){
		bQuest = false;
		return -1;
	    }
	}else{
	    offset = (off_t)lTmp;
	    bQuest = false;
	}	
    }

    bQuest = true;
    while(bQuest){
	iRet = readLong(&lTmp, "\n Please select how many records you want to read: ");

	if(iRet < 0 || lTmp < 0 || lTmp > (iMaxRecords - (int)offset)){
	    warnx("Input failure");
	    printf("\n Try again?");
	    printf("\n [0] N0 ");
	    printf("\n [everything else] Yes");
	    iRet = readLong(&lTmp, "\n Please select an option: ");
	    if(lTmp == 0){
		bQuest = false;
		return -1;
	    }
	}else{
	    length = (size_t)lTmp;
	    bQuest = false;
	}	
	/*
	   length = (size_t)lTmp;
	   bQuest = false;*/
    }

    //char strData[length];
    //char *strData;
    //uint8_t strData[length * iRecordSize];
    char strData[length * iRecordSize];
    //printf("\n length: %lu offset %d (int)sizeof(strData) %d \n", length, (int)offset, (int)sizeof(strData));

    iRet = mifare_desfire_read_records( tag, file_no, offset, length, &strData);
    if(iRet < 0){
	warnx ("Reading record failed");
	iRet = printLastPiccError(tag);
	printf("\n You can try other communication settings");
	printf("\n [0] N0 ");
	printf("\n [everything else] Yes");
	iRet = readLong(&lTmp, "\n Please select an option: ");
	if(lTmp == 0){
	    return -1;
	}else{
	    while(bLoop){

		iRet = askCS(&cs);
		if(iRet < 0)
		    return EXIT_FAILURE;

		iRet = mifare_desfire_read_records_ex( tag, file_no, offset, length, &strData, cs);
		if(iRet < 0){
		    warnx(" Reading records with communication settings failed");
		    iRet = printLastPiccError(tag);
		    printf("\n Try again");
		    printf("\n [0] N0 ");
		    printf("\n [everything else] Yes");
		    iRet = readLong(&lTmp, "\n Please select an option: ");
		    if(lTmp == 0){
			return -1;
		    }else{
			bLoop = true;
		    }
		}else{
		    bLoop = false;
		}
	    }//bLoop
	}
    }

    printf("\n Data(%d Bytes) : \n%s\n --- \n", iRet, strData);

    return iRet;
}

int 
clearRecordFile(MifareTag tag, uint8_t file_no){
    int iRet = 0;
    long lSel = 0;

    printf("\n Do you really want to clear this record file?");
    printf("\n [0]N0");
    printf("\n [<everything else>]Yes");
    iRet = readLong(&lSel, "\n Please select an option: ");

    if(lSel == 0)return 0;

    iRet = mifare_desfire_clear_record_file(tag, file_no);
    if(iRet < 0){
	printf("\n Record file not cleared");
    }else{
	printf("\n Record file sucessfully cleared");
    }

    printf("\n");
    return iRet;
}

int 
commitTransaction(MifareTag tag){
    int iRet = 0;
    long lSel = 0;

    printf("\n Do you really want to commit this transaction?");
    printf("\n [0]N0");
    printf("\n [<everything else>]Yes");
    iRet = readLong(&lSel, "\n Please select an option: ");

    if(lSel == 0)return 0;

    iRet = mifare_desfire_commit_transaction(tag);
    if(iRet < 0){
	warnx(" Transaction not commited");
	iRet = printLastPiccError(tag);
    }else{
	printf("\n Transaction sucessfully commited");
    }

    printf("\n");
    return iRet;
}

int 
abortTransaction(MifareTag tag){
    int iRet = 0;
    long lSel = 0;

    printf("\n Do you really want to abort this transaction?");
    printf("\n [0]N0\n");
    printf("\n [<everything else>]Yes\n");

    iRet = readLong(&lSel, "");

    if(lSel == 0)return 0;

    iRet = mifare_desfire_abort_transaction(tag);
    if(iRet < 0){
	printf("\n Transaction not aborted");
    }else{
	printf("\n Transaction sucessfully aborted");
    }

    return iRet;
}

int 
getFileSettings(MifareTag tag, uint8_t fn){
    int iRet = 1;
    struct mifare_desfire_file_settings set;

    iRet = mifare_desfire_get_file_settings(tag, fn, &set);

    if(set.file_type == MDFT_STANDARD_DATA_FILE){
	printf("\n MDFT_STANDARD_DATA_FILE ");
    }else if(set.file_type == MDFT_BACKUP_DATA_FILE){
	printf("\n MDFT_BACKUP_DATA_FILE");
    }else if(set.file_type == MDFT_VALUE_FILE_WITH_BACKUP){
	printf("\n MDFT_VALUE_FILE_WITH_BACKUP");
    }else if(set.file_type == MDFT_LINEAR_RECORD_FILE_WITH_BACKUP){
	printf("\n MDFT_LINEAR_RECORD_FILE_WITH_BACKUP");
    }else if(set.file_type == MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP){
	printf("\n MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP");
    }

    printf("\n  0x%02x (communication_settings)", set.communication_settings);
    printf("\n  0x%02x (access_rights)", set.access_rights);

    if(set.file_type == MDFT_STANDARD_DATA_FILE){
	printf("\n Standard File Values:");
	printf("\n  File size: %d Byte", set.settings.standard_file.file_size);
    }else if(set.file_type == MDFT_VALUE_FILE_WITH_BACKUP){
	printf("\n Value File Values:");
	printf("\n  %d lower_limit", set.settings.value_file.lower_limit);
	printf("\n  %d upper_limit", set.settings.value_file.upper_limit);
	printf("\n  %d limited_credit_value", set.settings.value_file.limited_credit_value);
	printf("\n  %d limited_credit_enabled", set.settings.value_file.limited_credit_enabled);	
    }else if(set.file_type == MDFT_LINEAR_RECORD_FILE_WITH_BACKUP){
	printf("\n Linear Record File Values:");
	printf("\n  %d record_size", set.settings.linear_record_file.record_size);
	printf("\n  %d max_number_of_records", set.settings.linear_record_file.max_number_of_records);
	printf("\n  %d current_number_of_records", set.settings.linear_record_file.current_number_of_records);
    }
    printf("\n");
    return iRet;
}

int 
getVersion(MifareTag tag){
	int iRet = 0;
	struct mifare_desfire_version_info version_info;

	iRet = mifare_desfire_get_version(tag, &version_info);
	if(iRet < 0){
		warnx(" Getting version failed");
		iRet = printLastPiccError(tag);
	}else{
		printf("\n Hardware: ");
		printf("\n  vendor_id: %d", version_info.hardware.vendor_id);
		printf("\n  type: %d", version_info.hardware.type);
		printf("\n  subtype: %d", version_info.hardware.subtype);
		printf("\n  version_major: %d", version_info.hardware.version_major);
		printf("\n  version_minor: %d", version_info.hardware.version_minor);
		printf("\n  storage_size: %d", version_info.hardware.storage_size);
		printf("\n  protocol: %d", version_info.hardware.protocol);
		printf("\n Software: ");
		printf("\n  vendor_id: %d", version_info.software.vendor_id);
		printf("\n  type: %d", version_info.software.type);
		printf("\n  subtype: %d", version_info.software.subtype);
		printf("\n  version_major: %d", version_info.software.version_major);
		printf("\n  version_minor: %d", version_info.software.version_minor);
		printf("\n  storage_size: %d", version_info.software.storage_size);
		printf("\n  protocol: %d", version_info.software.protocol);
		printf("\n Other data: ");
		printf("\n  uid:");
		int uid_len = 7;
		for(int i = 0; i < uid_len; i++){
			printf(" %02x", version_info.uid[i]);
		}
		printf("\n  batch_number:");
		int batch_number_len = 5;
		for(int i = 0; i < batch_number_len; i++){
			printf(" %d", version_info.batch_number[i]);
		}
		printf("\n  production_week: %d", version_info.production_week);
		printf("\n  production_year: %d", version_info.production_year);
		printf("\n");
	}

	return iRet;
}

int
getKeyVersion(MifareTag tag){
    int iRet = 0;
    long lTmp = 0;
    uint8_t key_no = 0;
    uint8_t version = 0;
    bool bQuest = true;

    while(bQuest){
	iRet = readUint8(&key_no, "\n Please enter the key number(0-13): ");
	if(key_no > 13 || iRet < 0){
	    printf("\n Input error");
	    printf("\n Try again?");
	    printf("\n [0] N0");
	    printf("\n [everything else] Yes");

	    iRet = readLong(&lTmp, "\n Please select an option: ");
	    if(lTmp == 0){
		bQuest = false;
		break;
	    }else{
		continue;
	    }
	}
	iRet = mifare_desfire_get_key_version(tag, key_no, &version);
	printf(" Key %d at version: %d", key_no, version);
	bQuest = false;
    }

    printf("\n");
    return iRet;
}

int
getCardUid(MifareTag tag){
    int iRet = 0;
    char *strUID;

    printf("\n");

    printf("\n ToDo: This can only be applied to a ev1 Tag\n");

    iRet = mifare_desfire_get_card_uid( tag, &strUID);
    if(iRet < 0){
	warnx("Getting card uid failed");
	iRet = printLastPiccError(tag);
    }else{
	printf("\n UID: %s", strUID);
    }

    printf("\n");
    return iRet;
}

int
freeMem(MifareTag tag){
    int iRet = 0;
    uint32_t size = 0;

    printf("\n ToDo: These options can only be applied to a ev1 Tag\n");

    printf("\n");	

    iRet = mifare_desfire_free_mem(tag, &size);
    if(iRet < 0){
	warnx ("Getting free memory failed");
    }else{
	printf("\n  Free memory: %d Byte", size);
    }

    printf("\n");
    return iRet;
}

int 
deleteFile(MifareTag tag, uint8_t file_no){
    int iRet = 1;
    long lSel = 0;

    printf("\n Do you really want to delete this file?");
    printf("\n [0]N0");
    printf("\n [<everything else>]Yes");

    iRet = readLong(&lSel, "\n Please select an option: ");

    if(lSel == 0)return 0;

    iRet = mifare_desfire_delete_file(tag, file_no);
    if(iRet < 0){
	warnx("Deletion failed");
	iRet = printLastPiccError(tag);
    }else{
	printf("\n File sucessfully deleted");
    }

    printf("\n");
    return iRet;
}

int 
selectApplication(MifareTag tag, MifareDESFireAID *aids, size_t *aid_count, long *selection){
    int iRet = 0;
    MifareDESFireAID *aidsTmp = NULL;
    MifareDESFireAID aidTmp;
    size_t aid_countTmp = 0;
    long lSel = 0;
    bool bQuest = true;
    printf("\n");

    iRet = mifare_desfire_select_application (tag, NULL); //Need to select Masterapplication und authenticate first
    if(iRet < 0){
	if(mifare_desfire_last_picc_error(tag) == PERMISSION_ERROR){
	    uint8_t key_data_null[8] = { 0,0,0,0,0,0,0,0};
	    MifareDESFireKey key = mifare_desfire_des_key_new_with_version (key_data_null);
	    iRet = mifare_desfire_authenticate(tag, 0, key);
	    if(iRet < 0){
		printf("\n You need to authenticate first");
		iRet = authenticate(tag);				
	    }
	}
    }

    printf("\n Do you want to select the master application?");
    printf("\n [0]N0 ");
    printf("\n [everything else] Yes");
    iRet = readLong(&lSel, "\n Please select an option: ");
    if(lSel != 0){
	iRet = mifare_desfire_select_application (tag, NULL);
	if(iRet < 0){
	    warnx(" Selecting master application failed");
	    iRet = printLastPiccError(tag);
	    return -1;
	}else{
	    printf("\n Master application successfully selected");
	    lSel = -1;
	    *selection = lSel;
	    return 1;
	}
    }

    iRet = mifare_desfire_get_application_ids (tag, &aidsTmp, &aid_countTmp);
    if(iRet < 0){
	warnx(" Getting application ids failed");
	iRet = printLastPiccError(tag);
	return -1;
    }

    aids = aidsTmp;
    *aid_count = aid_countTmp;

    if(aid_countTmp == 0){
	printf("\n No application available -> Selecting master application");
	iRet = mifare_desfire_select_application (tag, NULL);
	if(iRet < 0){
	    warnx(" Selecting master application failed");
	    iRet = printLastPiccError(tag);
	    return -1;
	}else{
	    printf("\n Master application successfully selected");
	    lSel = -1;
	    *selection = lSel;
	    return 1;
	}
    }else if(aid_countTmp == 1){
	printf("\n Autoselecting only application");
	iRet = mifare_desfire_select_application (tag, aidsTmp[0]);
	if(iRet < 0){
	    warnx(" Autoselecting only application failed");
	    iRet = printLastPiccError(tag);
	    return -1;
	}else{
	    printf("\n Autoselected only application: ");
	    lSel = 0;
	    *selection = lSel;
	    return 1;
	}
    }else {// aid_countTmp > 1
	while(bQuest){
	    printf("\n--- Available Applications(%zu): ", aid_countTmp);

	    for(int i=0; i<aid_countTmp; i++){
		printf("\n     [%d] %02x ", i, mifare_desfire_aid_get_aid(aidsTmp[i]));
	    }

	    iRet = readLong(&lSel, "\n     Please select an option: ");
	    if(lSel < 0 || lSel > (long)aid_countTmp){
		printf("\n Selection out of range");
		printf("\n Try again");
		printf("\n [0] N0 ");
		printf("\n [everything else] Yes");
		iRet = readLong(&lSel, "\n Please select an option: ");
		if(lSel == 0){
		    printf("\n Falling back to master application");
		    iRet = mifare_desfire_select_application (tag, NULL);
		    if(iRet < 0){
			warnx(" Selecting master application failed");
			iRet = printLastPiccError(tag);
			return -1;
		    }else{
			printf("\n Master application successfully selected");
			lSel = -1;
			*selection = lSel;
			return 1;
		    }
		}else{
		    bQuest = true;
		    continue;
		}		
	    }else{
		printf("\n Selecting application");
		iRet = mifare_desfire_select_application (tag, aidsTmp[lSel]);
		if(iRet < 0){
		    warnx(" Selecting application failed");
		    iRet = printLastPiccError(tag);
		    printf(" -> falling back to master application");
		    iRet = mifare_desfire_select_application (tag, NULL);
		    if(iRet < 0){
			warnx(" Selecting master application failed");
			iRet = printLastPiccError(tag);
			return -1;
		    }else{
			printf("\n Master application successfully selected");
			lSel = -1;
			*selection = lSel;
			return 1;
		    }
		}else{
		    printf("\n Application successfully selected");
		    *selection = lSel;
		    return 1;					
		}

	    }// lSel in range
	}//while(bQuest)
    }// aid_countTmp > 1

    printf("\n");
    return iRet;
}

int
selectMasterApplication(MifareTag tag){
    int iRet = 0;

    printf("\n");

    printf("\n ToDo: Display selection NIY");	

    iRet = mifare_desfire_select_application (tag, NULL);
    if(iRet < 0){
	warnx(" Selection of master application failed.");
	iRet = printLastPiccError(tag);
    }else{
	printf("\n Master application selected");
    }

    printf("\n");
    return iRet;
}

int 
deleteApplication(MifareTag tag, MifareDESFireAID aid){
    int iRet = 0;
    long lSel = 0;

    printf("\n Do you really want to delete this application?");
    printf("\n [0]N0");
    printf("\n [<everything else>]Yes");
    iRet = readLong(&lSel, "\n Please select an option: ");

    if(lSel == 0)return 0;

    iRet = mifare_desfire_delete_application(tag, aid);
    if(iRet < 0){
	printf("\n Deletion failed");
    }else{
	printf("\n Application sucessfully deleted");
    }

    printf("\n");
    return iRet;
}

int 
formatPicc(MifareTag tag){
    int iRet = 0;
    long lSel = 0;

    printf("\n Do you really want to format this card?");
    printf("\n [0]N0");
    printf("\n [<everything else>]Yes\n");

    iRet = readLong(&lSel, "\n Please select an option: ");

    if(lSel == 0)return 0;

    iRet = mifare_desfire_select_application (tag, NULL);

    uint8_t key_data_null[8] = { 0,0,0,0,0,0,0,0};
    MifareDESFireKey key = mifare_desfire_des_key_new_with_version (key_data_null);
    iRet = mifare_desfire_authenticate(tag, 0, key);
    if(iRet < 0){
	printf("\n You need to authenticate first");
	iRet = authenticate(tag);				
    }

    iRet = mifare_desfire_format_picc(tag);
    if(iRet < 0){
	printf("\n PICC format failed");
	iRet = printLastPiccError(tag);
    }else{
	printf("\n Card sucessfully deleted");
    }

    printf("\n");
    return iRet;
}

int 
getKeySettings(MifareTag tag){
    int iRet = EXIT_SUCCESS;
    uint8_t settings = 0;
    uint8_t max_keys = 0;		

    //ToDo: Select Master application and try to authenticate using standard null key

    iRet = mifare_desfire_get_key_settings(tag, &settings, &max_keys);
    if(iRet < 0){
	warnx(" Error retrieving key settings");
	iRet = printLastPiccError(tag);
	return EXIT_FAILURE;
    }

    printf("\n  Number of keys of selected application: %u ", max_keys); 
    printf("\n  Settings(%x): ", settings);

    printf("\n   configuration changeable: " );
    if((settings & 0x08)==8)
	printf("Yes");
    else
	printf("No");

    printf ("\n   PICC Master Key not required for create / delete: ");
    if((settings & 0x04)==4)
	printf("Yes");
    else
	printf("No");

    printf ("\n   Free directory list access without PICC Master Key: ");
    if((settings & 0x02)==2)
	printf("Yes");
    else
	printf("No");

    printf ("\n   Allow changing the Master Key: ");
    if((settings & 0x01)==1)
	printf("Yes");
    else
	printf("No");

    printf("\n");
    return iRet;
}


int 
readData(MifareTag tag, uint8_t file_no){
    int iRet = 1;
    int iFileSize = 0;
    int cs = 0;

    long lTmp = 0;
    long lSel = 0;

    bool bLoop = true;
    bool bQuest = true;

    off_t offset = 0;
    size_t length = 0;

    struct mifare_desfire_file_settings set;

    iRet = mifare_desfire_get_file_settings(tag, file_no, &set);
    iFileSize = set.settings.standard_file.file_size;
    char buffer[iFileSize];

    while(bQuest){
	iRet = readLong(&lTmp, "Please enter the offset: ");
	if(iRet < 0 || lTmp < 0 || lTmp > iFileSize){
	    warnx("Input failure");
	    printf("\n Try again?");
	    printf("\n [0] N0 ");
	    printf("\n [everything else] Yes");
	    iRet = readLong(&lTmp, "\n Please select an option: ");
	    if(lTmp == 0){
		bQuest = false;
		return -1;
	    }
	}else{
	    offset = (off_t)lTmp;
	    bQuest = false;
	}	
    }

    bQuest = true;
    while(bQuest){
	char strTmp[50];
	sprintf(strTmp, "Please enter the length(%d max): ", (iFileSize - (int)offset));
	iRet = readLong(&lTmp, strTmp);
	if(iRet < 0 || lTmp < 0 || lTmp > (iFileSize - (int)offset)){
	    warnx("Input failure");
	    printf("\n Try again?");
	    printf("\n [0] N0 ");
	    printf("\n [everything else] Yes");
	    iRet = readLong(&lTmp, "\n Please select an option: ");
	    if(lTmp == 0){
		bQuest = false;
		return -1;
	    }
	}else{
	    length = (size_t)lTmp;
	    bQuest = false;
	}	
    }

    iRet = mifare_desfire_read_data (tag, file_no, offset, length, buffer);
    if(iRet < 0){
	warnx ("Reading data failed");
	iRet = printLastPiccError(tag);
	printf("\n You can try other communication settings");
	printf("\n [0] N0 ");
	printf("\n [everything else] Yes");
	iRet = readLong(&lTmp, "\n Please select an option: ");
	if(lTmp == 0){
	    return -1;
	}else{
	    while(bLoop){

		iRet = askCS(&cs);
		if(iRet < 0)
		    return EXIT_FAILURE;

		iRet = mifare_desfire_read_data_ex( tag, file_no, offset, length, buffer, cs);
		if(iRet < 0){
		    warnx("Reading data with communication settings failed");
		    iRet = printLastPiccError(tag);
		    printf("\n Try again");
		    printf("\n [0] N0 ");
		    printf("\n [everything else] Yes");
		    iRet = readLong(&lTmp, "\n Please select an option: ");
		    if(lTmp == 0){
			return -1;
		    }else{
			bLoop = true;
		    }
		}else{
		    bLoop = false;
		}
	    }//bLoop
	}
    }

    buffer[length] = '\0';//ToDo: writes too much
    printf("\n---- Text (%d Bytes):\n%s\n----\n", (iFileSize - (int)offset), buffer);

    return iRet;
}

int 
writeData(MifareTag tag, uint8_t file_no){
    int iRet = 1;
    int iFileSize = 0;
    int cs = 0;
    int iLength = 0;

    long lTmp = 0;
    long lSel = 0;

    bool bLoop = true;
    bool bQuest = true;

    off_t offset = 0;
    size_t length = 0;
    void *data;
    //char *strData;
    struct mifare_desfire_file_settings set;

    iRet = mifare_desfire_get_file_settings(tag, file_no, &set);
    iFileSize = set.settings.standard_file.file_size;

    while(bQuest){
	iRet = readLong(&lTmp, "Please enter the offset: ");
	if(iRet < 0 || lTmp < 0 || lTmp > iFileSize){
	    warnx("Input failure");
	    printf("\n Try again?");
	    printf("\n [0] N0 ");
	    printf("\n [everything else] Yes");
	    iRet = readLong(&lTmp, "\n Please select an option: ");
	    if(lTmp == 0){
		bQuest = false;
		return -1;
	    }
	}else{
	    offset = (off_t)lTmp;
	    bQuest = false;
	}	
    }

    bQuest = true;
    while(bQuest){
	char strTmp[50];
	sprintf(strTmp, "Please enter the length(%d max): ", (iFileSize - (int)offset));
	iRet = readLong(&lTmp, strTmp);
	if(iRet < 0 || lTmp < 0 || lTmp > (iFileSize - (int)offset)){
	    warnx("Input failure");
	    printf("\n Try again?");
	    printf("\n [0] N0 ");
	    printf("\n [everything else] Yes");
	    iRet = readLong(&lTmp, "\n Please select an option: ");
	    if(lTmp == 0){
		bQuest = false;
		return -1;
	    }
	}else{
	    length = (size_t)lTmp;
	    bQuest = false;
	}	
    }

    char *strTmp;
    char strData[length+1];
    for(int i = 0; i < length+1; i++){
	strData[i] = '\0';
    }

    printf("\n Please enter your text(only the first %zu bytes will be writen):\n", length);

    strTmp = readline("");
    printf("\n---- ");

    if(strlen(strTmp) < length)
	iLength = strlen(strTmp);
    else
	iLength = length;

    memcpy(strData, strTmp, iLength);

    //printf("\n strData: %s\n strTmp: %s\n strlen(strData): %lu\n sizeof(strData): %lu\n strlen(strTmp): %lu\n iLength: %d ", strData, strTmp, strlen(strData), sizeof(strData), strlen(strTmp), iLength); 

    iRet = mifare_desfire_write_data (tag, file_no, offset, length, strData);
    if(iRet < 0){
	warnx ("Writing data failed");
	iRet = printLastPiccError(tag);
	printf("\n You can try other communication settings");
	printf("\n [0] N0 ");
	printf("\n [everything else] Yes");
	iRet = readLong(&lTmp, "\n Please select an option: ");
	if(lTmp == 0){
	    return -1;
	}else{
	    while(bLoop){

		iRet = askCS(&cs);
		if(iRet < 0)
		    return EXIT_FAILURE;

		iRet = mifare_desfire_write_data_ex( tag, file_no, offset, length, &strData, cs);
		if(iRet < 0){
		    warnx("Writing data with communication settings failed");
		    iRet = printLastPiccError(tag);					
		    printf("\n Try again");
		    printf("\n [0] N0 ");
		    printf("\n [everything else] Yes");
		    iRet = readLong(&lTmp, "\n Please select an option: ");
		    if(lTmp == 0){
			return -1;
		    }else{
			bLoop = true;
		    }
		}else{
		    bLoop = false;
		}
	    }//bLoop
	}
    }else{
	printf("\n Data writen successfully");
    }

    free(strTmp);

    printf("\n");
    return iRet;
}

int 
createCyclicRecordFile(MifareTag tag, uint8_t *files[], size_t count){
    int iRet = 0;
    bool bQuest = true;
    long lTmp = 0;
    uint8_t file_no = 0;
    uint8_t communication_settings = 0;
    uint16_t access_rights = 0;

    uint32_t record_size = 0;
    uint32_t max_number_of_records = 0;

    iRet = askFileNo(files, count, &file_no);
    if(iRet < 0)
	return -1;

    iRet = askCommunicationSettings( &communication_settings);
    if(iRet < 0)
	return -1;

    iRet = askAccessRights(&access_rights);
    if(iRet < 0)
	return -1;

    while(bQuest){
	iRet = readLong(&lTmp ,"\n Set record size: ");
	if(iRet <= 0 || lTmp < INT32_MIN || lTmp > INT32_MAX){
	    printf("\n ToDo: implement Try again");
	}else{
	    record_size = (int32_t)lTmp;
	    bQuest = false;
	}
    }

    bQuest = true;
    while(bQuest){
	iRet = readLong(&lTmp ,"\n Set maximum number of records: ");
	if(iRet <= 0 || lTmp < INT32_MIN || lTmp > INT32_MAX){
	    printf("\n ToDo: implement Try again");
	}else{
	    max_number_of_records = (uint32_t)lTmp;
	    bQuest = false;
	}
    }

    iRet = mifare_desfire_create_cyclic_record_file ( tag, file_no, communication_settings, access_rights, record_size, max_number_of_records);
    if (iRet < 0){
	warnx ("Cyclic record file creation failed");
	iRet = printLastPiccError(tag);
    }else{
	printf("\n Cyclic record file created successfully ");
    }

    return iRet;
}

int 
createLinearRecordFile(MifareTag tag, uint8_t *files[], size_t count){
    int iRet = 0;
    bool bQuest = true;
    long lTmp = 0;
    uint8_t file_no = 0;
    uint8_t communication_settings = 0;
    uint16_t access_rights = 0;

    uint32_t record_size = 0;
    uint32_t max_number_of_records = 0;

    iRet = askFileNo(files, count, &file_no);
    if(iRet < 0)
	return -1;

    iRet = askCommunicationSettings( &communication_settings);
    if(iRet < 0)
	return -1;

    iRet = askAccessRights(&access_rights);
    if(iRet < 0)
	return -1;

    while(bQuest){
	iRet = readLong(&lTmp ,"\n Set record size: ");
	if(iRet <= 0 || lTmp < INT32_MIN || lTmp > INT32_MAX){
	    printf("\n ToDo: implement Try again");
	}else{
	    record_size = (int32_t)lTmp;
	    bQuest = false;
	}
    }

    bQuest = true;
    while(bQuest){
	iRet = readLong(&lTmp ,"\n Set maximum number of records: ");
	if(iRet <= 0 || lTmp < INT32_MIN || lTmp > INT32_MAX){
	    printf("\n ToDo: implement Try again");
	}else{
	    max_number_of_records = (uint32_t)lTmp;
	    bQuest = false;
	}
    }

    iRet =  mifare_desfire_create_linear_record_file (tag, file_no, communication_settings, access_rights, record_size, max_number_of_records);
    if (iRet < 0){
	warnx ("Linear record file creation failed");
	iRet = printLastPiccError(tag);
    }else{
	printf("\n Linear record file created successfully ");
    }

    printf("\n");
    return iRet;
}

int 
createValueFile(MifareTag tag, uint8_t *files[], size_t count){
    int iRet = 0;
    bool bQuest = true;
    long lTmp = 0;
    uint8_t file_no = 0;
    uint8_t communication_settings = 0;
    uint16_t access_rights = 0;

    int32_t lower_limit = 0;
    int32_t upper_limit = 0;
    int32_t value = 0;
    uint8_t limited_credit_enable = 0;

    iRet = askFileNo(files, count, &file_no);
    if(iRet < 0)
	return -1;

    iRet = askCommunicationSettings( &communication_settings);
    if(iRet < 0)
	return -1;

    iRet = askAccessRights(&access_rights);
    if(iRet < 0)
	return -1;

    bQuest = true;
    while(bQuest){
	iRet = readLong(&lTmp ,"\n Set lower_limit: ");
	if(iRet <= 0 || lTmp < INT32_MIN || lTmp > INT32_MAX){
	    printf("\n ToDo: implement Try again");
	}else{
	    lower_limit = (int32_t)lTmp;
	    bQuest = false;
	}
    }

    bQuest = true;
    while(bQuest){
	iRet = readLong(&lTmp ,"\n Set upper_limit: ");
	if(iRet <= 0 || lTmp < INT32_MIN || lTmp > INT32_MAX){
	    printf("\n ToDo: implement Try again");
	}else{
	    upper_limit = (int32_t)lTmp;
	    bQuest = false;
	}
    }

    bQuest = true;
    while(bQuest){
	iRet = readLong(&lTmp ,"\n Set value: ");
	if(iRet <= 0 || lTmp < INT32_MIN || lTmp > INT32_MAX){
	    printf("\n ToDo: implement Try again");
	}else{
	    value = (int32_t)lTmp;
	    bQuest = false;
	}
    }

    bQuest = true;
    while(bQuest){
	iRet = readLong(&lTmp ,"\n Set limited_credit_enable(255 max): ");
	if(iRet <= 0 || lTmp < 0 || lTmp > UINT8_MAX){
	    printf("\n ToDo: implement Try again");
	}else{
	    value = (int32_t)lTmp;
	    bQuest = false;
	}
    }

    iRet = mifare_desfire_create_value_file (tag, file_no, communication_settings, access_rights, lower_limit, upper_limit, value, limited_credit_enable);
    if (iRet < 0){
	warnx ("Value file creation failed");
	iRet = printLastPiccError(tag);
    }else{
	printf("\n Value file created successfully ");
    }

    printf("\n");
    return iRet;
}

int 
createBackupDataFile(MifareTag tag, uint8_t *files[], size_t count){
    int iRet = 0;
    bool bQuest = true;
    long lTmp = 0;
    uint8_t file_no = 0;
    uint8_t communication_settings = 0;
    uint16_t access_rights = 0;
    uint32_t file_size = 0;
    uint32_t freeMem = 0;

    iRet = askFileNo(files, count, &file_no);
    if(iRet < 0)
	return -1;

    iRet = askCommunicationSettings( &communication_settings);
    if(iRet < 0)
	return -1;

    iRet = askAccessRights(&access_rights);
    if(iRet < 0)
	return -1;

    iRet = mifare_desfire_free_mem(tag, &freeMem);

    while(bQuest){
	printf("\n %d Bytes of free memory available", freeMem);
	iRet = readLong( &lTmp, "\n Set file size to: ");
	if(lTmp < 0 || lTmp > freeMem){
	    printf("\n Input out of range ");
	    printf("\n Try again");
	    printf("\n [0] N0 ");
	    printf("\n [everything else] Yes");
	    iRet = readLong(&lTmp, "\n Please select an option: ");
	    if(lTmp == 0){
		return -1;
	    }else{
		bQuest = true;
		continue;
	    }		
	}else{
	    file_size = (uint32_t)lTmp;
	    bQuest = false;
	}	
    }

    iRet = mifare_desfire_create_backup_data_file (tag, file_no, communication_settings, access_rights, file_size);
    if (iRet < 0){
	warnx ("Backup data file creation failed");
	iRet = printLastPiccError(tag);
    }else{
	printf("\n Backup data file created successfully ");
    }

    printf("\n");
    return iRet;
}

int
createStdDataFile(MifareTag tag, uint8_t *files[], size_t count){
    int iRet = 1;
    int iLoop = 1;
    long lSel = 0;
    long lFNoTmp = 0;
    bool bQuest = true;
    long lTmp = 0;

    uint8_t file_no = 0;
    uint8_t communication_settings = 0;
    uint16_t access_rights = 0;
    uint32_t file_size = 1;

    iRet = askFileNo(files, count, &file_no);
    if(iRet < 0)
	return -1;

    iRet = askCommunicationSettings( &communication_settings);
    if(iRet < 0)
	return -1;

    iRet = askAccessRights(&access_rights);
    if(iRet < 0)
	return -1;

    while(bQuest){
	iRet = readLong(&lTmp ,"\n Set file size: ");
	if(iRet <= 0 || lTmp < INT32_MIN || lTmp > INT32_MAX){
	    printf("\n ToDo: implement Try again");
	}else{
	    file_size = (int32_t)lTmp;
	    bQuest = false;
	}
    }

    iRet = mifare_desfire_create_std_data_file(tag, file_no, communication_settings, access_rights, file_size);
    if (iRet < 0){
	warnx ("File creation failed");
	iRet = printLastPiccError(tag);
    }else{
	printf("\n File created successfully ");
    }

    printf("\n");
    return iRet;
}


int
createApplication(MifareTag tag){
    int iRet = 1;
    long lKey = 0;
    bool bLoop = true;
    MifareDESFireAID aid;
    uint8_t cs;
    uint8_t key_count;
    uint32_t iAid;

    char *strAid;
    char *endptr;

    strAid = readline("\n Please enter an application id(3 Hex-Byte ->example: BEEFBE): ");
    char strtmp[strlen(strAid)+1];
    memcpy(strtmp, strAid, strlen(strAid));
    strtmp[strlen(strAid)+1]='\0';

    iAid = strtol(strAid, &endptr, 16);

    printf("\n Recognized aid: %02x(decimal: %d) \n", iAid, iAid);

    aid = mifare_desfire_aid_new(iAid);

    iRet = askCommunicationSettings(&cs);

    while(bLoop > 0){
	iRet = readLong( &lKey, "\n How many keys do you want to use with this application(13 max): ");
	if((lKey < 0) || (lKey > 13)){
	    long lOpt = 0;

	    bLoop = true;

	    printf("\n Key count out of range");
	    printf("\n   Try again? ");
	    printf("\n   [0] N0");
	    printf("\n   [1] Yes");
	    iRet = readLong(&lOpt, "\n   Please select an option: ");
	    if(iRet <= 0)
		continue;

	    if(lOpt == 0){
		return -1;
	    }else{
		continue;
	    }
	}else{
	    key_count = (uint8_t)lKey;
	    break;
	}
    }

    iRet = mifare_desfire_create_application( tag, aid, cs, key_count);
    if(iRet < 0){
	warnx(" Application creation failed");
	iRet = printLastPiccError(tag);

    }else{
	printf("\n Application successfully created.");
    }

    printf("\n");
    return iRet;
}

//------------------------------------------------------------------------------------- gui

int 
doFileLevel(MifareTag tag){
    int iRet = 1;
    long lSel = 0;
    long lOpt = 0;

    bool bLoop = true;
    bool bSelFile = false;

    uint8_t *files = NULL;
    size_t file_count;
    struct mifare_desfire_file_settings settings;
    uint8_t filesNr;

    printf("\n==== Entering File Level ");

    while(bLoop) {
	if(!bSelFile){
	    printf("\n---- Scanning for available files: ");

	    iRet = mifare_desfire_get_file_ids(tag, &files, &file_count);
	    if (iRet < 0){
		uint8_t error = mifare_desfire_last_picc_error(tag);
		if(error == AUTHENTICATION_ERROR){
		    printf("\n Sorry, you need to authenticate first");
		    bLoop = false;
		    break;
		}else{
		    warnx ("Getting file IDs failed");
		    iRet = printLastPiccError(tag);
		    printf(" occured -> returning");
		    bLoop = false;
		    break;
		}
	    }

	    printf("\n---- Available Files(%zu): ", file_count);

	    for(int i=0; i<file_count; i++){
		printf("\n      [%d] %02x ", i, files[i]);
	    }

	    if(file_count == 0){			
		printf("\n      No file found ");
		printf("\n      [ 0] 0uit file level) ");			
		printf("\n      [ 1] createStdDataFile() ");
		printf("\n      [ 2] createBackupDataFile() ");
		printf("\n      [ 3] createValueFile() ");
		printf("\n      [ 4] createLinearRecordFile() ");
		printf("\n      [ 5] createCyclicRecordFile() ");
		iRet = readLong(&lOpt, "\n      Please select an Option: ");
		if(lOpt == 0){
		    bLoop = false;
		    break;
		}else if(lOpt == 1){
		    iRet = createStdDataFile(tag, &files, file_count);
		    continue;
		}else if(lOpt == 2){
		    iRet = createBackupDataFile(tag, &files, file_count);
		    continue;
		}else if(lOpt == 3){
		    iRet = createValueFile(tag, &files, file_count);
		    continue;
		}else if(lOpt == 4){
		    iRet = createLinearRecordFile(tag, &files, file_count);
		    continue;
		}else if(lOpt == 5){
		    iRet = createCyclicRecordFile(tag, &files, file_count);
		    continue;
		}else if(lOpt == 1){
		    iRet = createCyclicRecordFile(tag, &files, file_count);
		    continue;
		}else{
		    //printf("\n     [Not Implemented Yet]");
		    continue;
		}
	    }

	    if(file_count == 1){
		lSel = 0;
		printf("\n      Autoselected only file");
	    }else if(file_count > 1){
		iRet = readLong(&lSel, "\n      Please select a file: ");
		if(iRet <= 0)
		    continue;
	    }
	    filesNr = files[lSel];

	    iRet = mifare_desfire_get_file_settings(tag, files[lSel], &settings);
	    if (iRet < 0){
		warnx ("Getting file settings failed");
		iRet = printLastPiccError(tag);
	    }

	    bSelFile = true;

	}else{
	    printf("\n     Selected File: ");
	    printf("\n      [%ld] %02x ", lSel, filesNr);
	    printf("\n");
	}


	if(file_count > 0) {
	    printf("\n---- helper operations: ");
	    printf("\n      [ 0] selectFile");
	    printf("\n      [ 1] printAccessRights()");
	    printf("\n      [ 2] authenticate() ");
	    printf("\n      [ 9] leave File Level");
	    printf("\n---- File-level operations: ");
	    printf("\n      [11] getFileSettings()");
	    printf("\n      [12] changeFileSettings()");
	    printf("\n      [13] deleteFile()");
	    printf("\n      [14] createStdDataFile()");
	    printf("\n      [15] createBackupDataFile()");
	    printf("\n      [16] createValueFile()");
	    printf("\n      [17] createLinearRecordFile()");
	    printf("\n      [18] createCyclicRecordFile()");

	    printf("\n---- Data-level operations: ");


	    if(settings.file_type == MDFT_STANDARD_DATA_FILE){
		printf("\n      (Recognized a Standard Data File:)");
		printf("\n      [20] readData()");
		printf("\n      [21] writeData()");
	    }else if(settings.file_type == MDFT_BACKUP_DATA_FILE){
		printf("\n      (Recognized a Backup Data File)");
		printf("\n      []");
	    }else if(settings.file_type == MDFT_VALUE_FILE_WITH_BACKUP){
		printf("\n      (Recognized a Value File)");
		printf("\n      [30] getValue()");
		printf("\n      [31] credit()");
		printf("\n      [32] debit()");
		printf("\n      [33] limitedCredit()");
	    }else if(settings.file_type == MDFT_LINEAR_RECORD_FILE_WITH_BACKUP){
		printf("\n      (Recognized a Linear Record File)");
		printf("\n      [40] writeRecord()");
		printf("\n      [41] readRecords()");
		printf("\n      [42] clearRecordFile()");
	    }else if(settings.file_type == MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP){
		printf("\n      (Recognized a Cyclic Record File)");
		printf("\n      [40] writeRecord()");
		printf("\n      [41] readRecords()");
		printf("\n      [42] clearRecordFile()");
	    }

	    printf("\n      [50] commitTransaction()");
	    printf("\n      [51] abortTransaction()");	
	    iRet = readLong(&lOpt, "\n      Please select an Option: ");

	    if(lOpt == 0){
		free(files);
		files = NULL;
		bSelFile = false;
	    }else if(lOpt == 1){
		iRet = printAccessRights(tag, files[lSel]);
	    }else if(lOpt == 2){
		iRet = authenticate(tag);
	    }else if(lOpt == 9){
		bLoop = false;
	    }else if(lOpt == 11){
		iRet = getFileSettings(tag,files[lSel]); 
	    }else if(lOpt == 12){
		iRet = changeFileSettings(tag,files[lSel]); 
	    }else if(lOpt == 13){
		iRet = deleteFile(tag,files[lSel]);
		bSelFile = false;
	    }else if(lOpt == 14){
		iRet = createStdDataFile(tag, &files, file_count);
	    }else if(lOpt == 15){
		iRet = createBackupDataFile(tag, &files, file_count);
	    }else if(lOpt == 16){
		iRet = createValueFile(tag, &files, file_count);
	    }else if(lOpt == 17){
		iRet = createLinearRecordFile(tag, &files, file_count);
	    }else if(lOpt == 18){
		iRet = createCyclicRecordFile(tag, &files, file_count);
	    }else if(lOpt == 20){
		iRet = readData(tag,files[lSel]);
	    }else if(lOpt == 21){
		iRet = writeData(tag,files[lSel]);
	    }else if(lOpt == 30){
		iRet = getValue(tag,files[lSel]);
	    }else if(lOpt == 31){
		iRet = credit(tag,files[lSel]);
	    }else if(lOpt == 32){
		iRet = debit(tag,files[lSel]);
	    }else if(lOpt == 33){
		iRet = limitedCredit(tag,files[lSel]);
	    }else if(lOpt == 40){
		iRet = writeRecord(tag,files[lSel]);
	    }else if(lOpt == 41){
		iRet = readRecords(tag,files[lSel]);
	    }else if(lOpt == 42){
		iRet = clearRecordFile(tag,files[lSel]);
	    }else if(lOpt == 50){
		iRet = commitTransaction(tag);
	    }else if(lOpt == 51){
		iRet = abortTransaction(tag);
	    }else 
		printf("\n     [Not Implemented Yet]");

	}else{ //file_count == 0
	    printf("\n     No File found!");

	}
    }

    printf("\n<----Leaving File Level\n");
    return iRet;
}

int
doApplicationLevel(MifareTag tag){
    int iRet = 1;
    long lSel = 0;	
    long lOpt = 0;

    bool bSelection = false;
    bool bLoop = true;

    MifareDESFireAID *aids = NULL;
    size_t aid_count;
    uint32_t mifareDesfireAIDNr = 0;

    printf("\n=== Entered Application Level ");

    iRet = mifare_desfire_get_application_ids (tag, &aids, &aid_count);

    while(bLoop){
	if(bSelection == false){
	    iRet = selectApplication(tag, aids, &aid_count, &lSel);
	    if(lSel >= 0){
		mifareDesfireAIDNr = mifare_desfire_aid_get_aid(aids[lSel]);
		printf("\n     [%ld] %02x ", lSel, mifareDesfireAIDNr);
	    }
	    bSelection = true;
	    printf("\n");			
	}else{
	    printf("\n--- Selected application: ");
	    if(lSel == -1)
		printf("\n Master application");
	    else
		printf("\n     [%ld] %02x ", lSel, mifareDesfireAIDNr);
	    printf("\n");			
	}
	printf("\n--- helper operations: ");

	printf("\n     [ 0] selectApplication ");
	printf("\n     [ 1] doFileLevel() ");
	printf("\n     [ 2] selectMasterApplication() ");
	printf("\n     [ 3] printVersionKeySettings() ");
	printf("\n     [ 9] leaveApplicationLevel ");

	printf("\n--- Application-level operations: ");
	printf("\n     [10] selectApplication() ");
	printf("\n     [11] authenticate()");
	printf("\n     [12] getKeySettings()");
	printf("\n     [13] changeKeySettings() ");
	printf("\n     [14] changeKey() ");
	printf("\n     [15] getKeyVersion() ");
	printf("\n     [16] createApplication()");
	printf("\n     [17] deleteApplication()");

	iRet = readLong(&lOpt, "\n     Please select an option: ");
	if(iRet <= 0)
	    continue;

	if(lOpt == 0){
	    bSelection = false;
	}else if(lOpt == 1){
	    iRet = doFileLevel(tag);
	}else if(lOpt == 2){
	    iRet = selectMasterApplication(tag);
	}else if(lOpt == 3){
	    iRet = printVersionKeySettings(tag);
	}else if(lOpt == 9){
	    bLoop = false;
	}else if(lOpt == 10){
	    iRet = selectApplication(tag, aids, &aid_count, &lSel);
	}else if(lOpt == 11){
	    iRet = authenticate(tag);
	}else if(lOpt == 12){
	    iRet = getKeySettings(tag);
	}else if(lOpt == 13){
	    iRet = changeKeySettings(tag);
	}else if(lOpt == 14){
	    iRet = changeKey(tag);
	}else if(lOpt == 15){
	    iRet = getKeyVersion(tag);
	}else if(lOpt == 16){
	    iRet = createApplication(tag);
	}else if(lOpt == 17){
	    iRet = deleteApplication(tag, aids[lSel]);
	}	
    }

    printf("\n<---Leaving Application Level\n");
    mifare_desfire_free_application_ids(aids);
    return iRet;
}

int
doCardLevel(nfc_device_t *device){
    int iRet = 1;
    int iTagCount = 0;
    long lSel = 0;
    bool bLoop=true;
    long lOpt=0;
    int iErr=0;
    MifareTag *tags = NULL;

    printf("\n== Entered Card Level ");

    while(bLoop){
        if(tags == NULL){
            printf("\n-- Scanning for available cards: ");

            tags = freefare_get_tags(device);
            if (!tags) 
                warnx ("Error listing tags.");

            for (iTagCount = 0; tags[iTagCount]; iTagCount++) {
                printf("\n    [%d]: %s (UID: %s)", iTagCount, freefare_get_tag_friendly_name (tags[iTagCount]), freefare_get_tag_uid (tags[iTagCount]));

                if (DESFIRE != freefare_get_tag_type (tags[iTagCount])){
                    printf("\n         Not a DESFire Card !!!");
                }
            }

            if(iTagCount == 0){
                printf("\n   Please place a card on the PCD and continue?");
                printf("\n   [0]N0(0uit Card Level)");
                printf("\n   [1]Try again\n    ");
                iRet = readLong(&lOpt, "\n     Please select an option: ");
                if(iRet <= 0){
                    if(tags != NULL)
                        tags = NULL;
                    continue;
                }

                if(lOpt == 0){
                    bLoop = false;
                    break;
                }else{
                    freefare_free_tags(tags);
                    tags=NULL;
                    continue;
                }
            }else if(iTagCount == 1){
                lSel = 0;
                printf("\n    Autoselected only card");
            }else{
                iRet =  readLong(&lSel, "\n    Please select a card: ");
                if(iRet <= 0)
                    continue;
            }
        }else{
            printf("\n-- Selected card: ");
            printf("\n   [%d]: %s (UID: %s)", iTagCount, freefare_get_tag_friendly_name (tags[lSel]), freefare_get_tag_uid (tags[lSel]));
            printf("\n");
        }

        if (DESFIRE != freefare_get_tag_type (tags[lSel])){
            printf("\n-- Card Options: ");
            printf("\n    Not a DESFire card -> NIY");
            printf("\n    [0] selectOtherCard ");
            printf("\n    [9] leaveCardLevel ");
            iRet = readLong(&lOpt, "\n    Please select an Option: ");
            if(lOpt == 0){ 
                freefare_free_tags (tags);
                tags = NULL;
                continue;
            }else if(lOpt == 9){
                bLoop = false;
            }

        }else{
            iErr = mifare_desfire_connect (tags[lSel]);
            if (iErr < 0) {
                warnx ("Can't connect to Mifare DESFire target.");			
            }
            printf("\n-- helper operations: ");
            printf("\n    [ 0] selectOtherCard ");
            printf("\n    [ 1] doApplicationLevel() ");
            printf("\n    [ 2] printApplicationIDs() ");
            printf("\n    [ 9] leaveCardLevel");

            printf("\n-- Card-level operations: ");
            printf("\n    [10] getCardUid() ");
            printf("\n    [11] getVersion() ");
            printf("\n    [12] freeMem() ");
            printf("\n    [13] formatPicc() ");
            printf("\n    [14] setConfiguration() ");
            printf("\n    [15] setDefaultKey() ");

            iRet = readLong(&lOpt, "\n    Please select an Option: ");
            if(lOpt == 0){ 
                freefare_free_tags (tags);
                tags = NULL;
                continue;
            }else if(lOpt == 1)
                iRet = doApplicationLevel(tags[lSel]);
            else if(lOpt == 2)
                iRet = printApplicationIDs(tags[lSel]);
            else if(lOpt == 9)
                bLoop = false;
            else if(lOpt == 10)
                iRet = getCardUid(tags[lSel]);
            else if(lOpt == 11)
                iRet = getVersion(tags[lSel]);
            else if(lOpt == 12)
                iRet = freeMem(tags[lSel]);
            else if(lOpt == 13)
                iRet = formatPicc(tags[lSel]);
            else if(lOpt == 14)
                iRet = setConfiguration(tags[lSel]);
            else if(lOpt == 15)
                iRet = setDefaultKey(tags[lSel]);

            iErr = mifare_desfire_disconnect(tags[lSel]);
        }
    }//	while(iLoop>0)

    printf("\n<--Leaving Card Level. \n");
    freefare_free_tags (tags);
    return iRet;
}

int
doDevLevel(){
    int iRet = 1;
    bool bLoop = 1;
    long lSel = 0;
    long lOpt = 0;
    nfc_device_t *device = NULL;
    nfc_device_desc_t devices[8];
    size_t device_count;
    bool bDevSel = false;

    printf("\n= Entered Device Level ");

    while(bLoop){
	if(!bDevSel){
	    printf("\n- Scanning for available devices: ");
	    nfc_list_devices (devices, 8, &device_count);
	    if (!device_count)
		warnx ("No NFC device found.\n");

	    for (size_t d = 0; d < device_count; d++) {
		device = nfc_connect (&(devices[d]));
		if (!device) {
		    warnx (" nfc_connect() failed.");
		    continue;
		}
		printf("\n   [%zu] %1s",d, device->acName);
		nfc_disconnect(device);			
	    }

	    if(device_count == 0){
		printf("\n   No device found");
		printf("\n   Try again? ");
		printf("\n   [0] N0(0uit programm)");
		printf("\n   [1] Yes");
		iRet = readLong(&lOpt, "\n   Please select an option: ");
		if(iRet <= 0)
		    continue;

		if(lOpt == 0){
		    bLoop = false;
		    break;
		}else{
		    continue;
		}

	    }else if(device_count == 1){
		printf("\n   Autoselected only device");
		lSel = 0;
	    }else{
		if(readLong(&lSel, "\n   Please type the number of the device you want to select: ") <= 0)
		    continue;
	    }

	    device = nfc_connect (&(devices[lSel]));
	    if(!device)
		warnx(" Connecting to nfc device failed");
	    bDevSel = true;

	}else{
	    printf("\n- Selected Device: ");
	    printf("\n   [%ld] %1s", lSel, device->acName);
	    printf("\n");
	}

	printf("\n- Device Options: ");
	printf("\n   [0]selectOtherDevice");
	printf("\n   [1]doCardLevel() ");
	printf("\n   [2]printDevice() ");
	printf("\n   [9]leaveDeviceLevel ");
	iRet = readLong(&lOpt, "\n   Please select an Option: ");
	if(iRet <= 0)
	    continue;

	if(lOpt == 0){
	    nfc_disconnect (device);
	    device = NULL;
	    bDevSel = false;
	}else if(lOpt == 1)
	    iRet = doCardLevel(device);
	else if(lOpt == 2)
	    iRet = printDevice(device);
	else if(lOpt==9){
	    bLoop = 0;
	}
    }

    printf("\n<-Leaving Device Level\n");
    if(device!=NULL){
	nfc_disconnect (device);
	device = NULL;
    }
    return iRet;
}

    int
main(int argc, char *argv[])
{
    int iRet = EXIT_SUCCESS;

    if (argc > 1)
	errx (EXIT_FAILURE, "usage: %s", argv[0]);

    iRet = doDevLevel();

    printf("\n Bye bye! \n");
    return iRet;
} /* main() */

