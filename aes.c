// File encryption/decryption program written in C 
// Implementing AES in CBC mode with PKCS#7 padding 
// [!] This program is for educational and demonstration purposes only

/*
To use program:
First compile the source file
Then in the command line write (in order): 
[executable] [encrypt or decrypt] [key size in bits (128 or 192 or 256)] [key (16 or 24 or 32 bytes long)] [IV (16 bytes long)] [input file path] [output file path]
*/

// Omar 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/time.h>   

unsigned char sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

unsigned char getSBoxValue(unsigned char num) {
	return sbox[num];
}

unsigned char invsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb
, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e
, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25
, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92
, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84
, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06
, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b
, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73
, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e
, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b
, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4
, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f
, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef
, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61
, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

unsigned char getSBoxInv(unsigned char num) {
	return invsbox[num];
}

unsigned char Rcon[255] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
	0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
	0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
	0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
	0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
	0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
	0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
	0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
	0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
	0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
	0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
	0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
	0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
	0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
	0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
	0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
	0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
	0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
	0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb };

unsigned char getRconValue(unsigned char num) {
	return Rcon[num];
}

unsigned char galoisMultiplication(register unsigned char a, register unsigned char b) {
	register unsigned char res = 0;
	register unsigned char hi_bit_set;
	register int i;

	for (i = 0; i < 8; ++i) {
		if ((b & 1) == 1)
			res ^= a;
		hi_bit_set = (a & 0x80);
		a <<= 1;
		if (hi_bit_set == 0x80)
			a ^= 0x1b;
		b >>= 1;
	}

	return res;
}


/*
****************** KEY EXPANSION, CREATING AND ADDING THE ROUND KEYS START ******************/

void firstCol(unsigned char *word, int rconColNum) {
	//rotate the word 1 byte to the left
	unsigned char tmp = word[0];
	word[0] = word[1];
	word[1] = word[2];
	word[2] = word[3];
	word[3] = tmp;
	//Subbyte
	word[0] = getSBoxValue(word[0]);
	word[1] = getSBoxValue(word[1]);
	word[2] = getSBoxValue(word[2]);
	word[3] = getSBoxValue(word[3]);
	//XOR the output of the rcon operation with i to the first part (leftmost) only
	word[0] = word[0] ^ getRconValue(rconColNum);
}

void expandKey(unsigned char *expandedKey, unsigned char *key, register int keySize, register int expandedKeySize) {
	register int index = 0;
	register int rconCol = 1;
	//prev is a temp column array
	unsigned char prev[4] = { 0 };
	register int i, k;

	//put original key in expanded key
	for (i = 0; i < keySize; ++i)
		expandedKey[i] = key[i];

	//then add the key size to index
	index += keySize;

	//keep looping until expanded key is completely filled
	while (index < expandedKeySize) {
		//fill prev with preceding column
		register int pi = index - 4;
			prev[0] = expandedKey[pi + 0];
			prev[1] = expandedKey[pi + 1];
			prev[2] = expandedKey[pi + 2];
			prev[3] = expandedKey[pi + 3];

		//number of words per block: 128 bits -> 4 words | 192 bits -> 6 words | 256 bits -> 8 words
		//apply firstCol to the first column of every block
		if (index % keySize == 0) 
			firstCol(prev, rconCol++);

		// For 256 bit keys we add an extra sbox to the calculation 
		if (keySize == 32 && ((index % keySize) == 16)){
				prev[0] = getSBoxValue(prev[0]);
				prev[1] = getSBoxValue(prev[1]);
				prev[2] = getSBoxValue(prev[2]);
				prev[3] = getSBoxValue(prev[3]);
		}

		//XOR previous block's column with preceding column in the current block (for every column but the first one)
		//result is a new column
		for (k = 0; k < 4; ++k) {
			expandedKey[index] = expandedKey[index - keySize] ^ prev[k];
			++index;
		}
	}
}

void createARoundKey(unsigned char *expandedKey, unsigned char *roundKey) {
	register int col, row;
	//filling the round key column by column with the corresponding expanded key bytes
	for (col = 0; col < 4; ++col) {
		for (row = 0; row < 4; ++row) {
			roundKey[col + (row * 4)] = expandedKey[(col * 4) + row];
		}
	}
}

void addRoundKey(unsigned char *state, unsigned char *roundKey) {
	register int i;
	for (i = 0; i < 16; ++i)
		state[i] ^= roundKey[i];
}

/****************** KEY EXPANSION, CREATING AND ADDING THE ROUND KEYS END ******************
*/


/*
****************** PADDING START ******************/

/*function for adding additional bytes to original plaintext*/
unsigned char *pkcs7Pad(unsigned char *unpaddedInput, register int inputSize, int *output_size) {
	register int blockSize = 16;
	register int modulo = inputSize % blockSize;
	//paddingchar is the number of bytes to pad, (ex: if char is 10 then we pad the end with 10 chars)
	register unsigned char paddingChar = blockSize - modulo;
	//add number of chars to pad into output array
	register int outputSize = inputSize + paddingChar;
	//output array to fill
	unsigned char *paddedOutput = malloc(outputSize);

	*output_size = outputSize;

	//check if array is empty (null)
	if (paddedOutput == NULL)
		return paddedOutput;

	//fill output array with input array values
	memcpy(paddedOutput, unpaddedInput, inputSize);

	register int j;
	//pad output array with paddingChar until end
	for (j = inputSize; j < outputSize; ++j)
		paddedOutput[j] = paddingChar;

	return paddedOutput;
}

/*function which detects how many chars were added for padding then removes them*/
unsigned char *pkcs7Unpad(unsigned char *paddedInput, register int inputSize, int *output_size) {
	//last value in input array is the padding char, which says how much padding was used
	register unsigned char lastInputVal = paddedInput[inputSize - 1];

	// check if this casting will go wrong //
	register int outputSize = inputSize - lastInputVal;
	//assign output size
	*output_size = outputSize;

	//assign output array
	unsigned char *unpaddedOutput = malloc(outputSize);

	//check if array is empty (null)
	if (unpaddedOutput == NULL)
		return unpaddedOutput;

	//fill output array with all the elements of the padded input array until right before the padding chars
	memcpy(unpaddedOutput, paddedInput, outputSize);

	return unpaddedOutput;
}

/****************** PADDING END ******************
*/


/*
****************** ENCRYPTION FUNCTIONS START ******************/

void subBytes(unsigned char *state) {
	register int i;
	for (i = 0; i < 16; ++i)
		state[i] = getSBoxValue(state[i]);
}

void shiftRows(unsigned char *state) {
	register unsigned char temp;
	//row 1: shift 1 left
	temp = state[4];
	state[4] = state[5];
	state[5] = state[6];
	state[6] = state[7];
	state[7] = temp;
	//row 2: shift 2 left
	temp = state[8];
	state[8] = state[10];
	state[10] = temp;
	temp = state[9];
	state[9] = state[11];
	state[11] = temp;
	//row 3: shift 3 left
	temp = state[15];
	state[15] = state[14];
	state[14] = state[13];
	state[13] = state[12];
	state[12] = temp;
}

void mixColumns(unsigned char *state) {
	unsigned char column[4];
	unsigned char temp[4];
	register int i;
	// 4 columns
	for (i = 0; i < 4; ++i) {
		// fill column with state values	
			column[0] = state[i];
			column[1] = state[4 + i];
			column[2] = state[8 + i];
			column[3] = state[12 + i];

		// fill temp with column
			temp[0] = column[0];
			temp[1] = column[1];
			temp[2] = column[2];
			temp[3] = column[3];

		/*
		The fixed matrix for mixcolumns is:
		2 3 1 1
		1 2 3 1
		1 1 2 3
		3 1 1 2
		*/
		column[0] = galoisMultiplication(temp[0], 2) ^ galoisMultiplication(temp[1], 3) ^ galoisMultiplication(temp[2], 1) ^ galoisMultiplication(temp[3], 1);
		column[1] = galoisMultiplication(temp[0], 1) ^ galoisMultiplication(temp[1], 2) ^ galoisMultiplication(temp[2], 3) ^ galoisMultiplication(temp[3], 1);
		column[2] = galoisMultiplication(temp[0], 1) ^ galoisMultiplication(temp[1], 1) ^ galoisMultiplication(temp[2], 2) ^ galoisMultiplication(temp[3], 3);
		column[3] = galoisMultiplication(temp[0], 3) ^ galoisMultiplication(temp[1], 1) ^ galoisMultiplication(temp[2], 1) ^ galoisMultiplication(temp[3], 2);

		//put the values in column back in the state
			state[i] = column[0];
			state[4 + i] = column[1];
			state[8 + i] = column[2];
			state[12 + i] = column[3];
	}
}

/*the main function for aes ENCRYPTION*/
void aesEncrypt(unsigned char *state, unsigned char *expandedKey, register int nbRounds) {
	//acts like a temp variable
	unsigned char roundKey[16];
	
	//adding the first round key
	createARoundKey(expandedKey, roundKey);
	addRoundKey(state, roundKey);

	register int i;
	//all rounds before the last round
	for (i = 1; i < nbRounds; ++i) {
		createARoundKey(expandedKey + 16 * i, roundKey);
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, roundKey);
	}

	//last round
	createARoundKey(expandedKey + 16 * nbRounds, roundKey);
	subBytes(state);
	shiftRows(state);
	addRoundKey(state, roundKey);
}

/*this function recieves input state and the key, then encrypts the input and produces output cyphertext*/
unsigned char *encryptBlock(unsigned char *input, unsigned char *key, int keySize, int nbRounds) {
	unsigned char *expandedKey;
	int expandedKeySize = (16 * (nbRounds + 1));
	//128 bit block
	unsigned char block[16];
	unsigned char *output = malloc(16);
	register int i, j;
	//filling the block with input state
	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 4; ++j) {
			block[(i + (j * 4))] = input[(i * 4) + j];
		}
	}

	//condition that checks expandedkey size
	if ((expandedKey = malloc(expandedKeySize)) == NULL)
		return output;

	//expand the key into a 176, 208, 240 bytes expanded key
	expandKey(expandedKey, key, keySize, expandedKeySize);

	//encrypt block using the expanded key
	aesEncrypt(block, expandedKey, nbRounds);

	register int k, l;
	//filling output state with encrypted block
	for (k = 0; k < 4; ++k) {
		for (l = 0; l < 4; ++l) {
			output[(k * 4) + l] = block[(k + (l * 4))];
		}
	}
	return output;
}

/*main CBC encryption function (use after padding the plaintext)*/
unsigned char *cbcEncrypt(unsigned char *inputPPT, register int ptSize, unsigned char *IV, unsigned char *key, int keySize, int nbRounds) {

	//tempblock acts as input ("plaintext" block) and current block, prevblock acts as output (ciphertext block) and next block
	unsigned char tempBlock[16];
	unsigned char *prevBlock = NULL;

	//assign output array
	unsigned char *outputCT = malloc(ptSize);

	//check if array is empty (null)
	if (outputCT == NULL)
		return outputCT;

	register int i, j, k, l, m;

	//index for the input padded plaintext
	register int index = 0;
	register int isfirst = 1;

	//start cbc encryption chain
	for (i = 0; i < ptSize; i += 16) {

		//fill temp with current block
		register int tempcounter = 0;
		register int checkv = index + 16;
		for (j = index; j < checkv; ++j) {
			tempBlock[tempcounter] = inputPPT[j];
			++tempcounter;
		}

		if (isfirst != 1) {
		//if not at the start then XOR tempblock with the previous cipherblock
			for (l = 0; l < 16; ++l)
				tempBlock[l] ^= prevBlock[l];

			free(prevBlock);
		}
		else {
		// if this loop is at the start of the chain, if yes then XOR tempblock with the IV
			for (k = 0; k < 16; ++k)
				tempBlock[k] ^= IV[k];
		
		isfirst = 0;		
		}
		
		//encrypt current block
		prevBlock = encryptBlock(tempBlock, key, keySize, nbRounds);

		//put encrypted block into outputCT
		register int tempcounter2 = 0;
		register int lastv = index + 16;
		for (m = index; m < lastv; ++m) {
			outputCT[m] = prevBlock[tempcounter2];
			++tempcounter2;
		}
		//increment index to move to the next block
		index += 16;
	}

	return outputCT;
}

/****************** ENCRYPTION FUNCTIONS END ******************
*/


/*
****************** DECRYPTION FUNCTIONS START ******************/

void invSubBytes(unsigned char *state) {
	register int i;
	for (i = 0; i < 16; ++i)
		state[i] = getSBoxInv(state[i]);
}

void invShiftRows(unsigned char *state) {
	register unsigned char temp;
	//row 1: shift 1 right
	temp = state[7];
	state[7] = state[6];
	state[6] = state[5];
	state[5] = state[4];
	state[4] = temp;
	//row 2: shift 2 right
	temp = state[10];
	state[10] = state[8];
	state[8] = temp;
	temp = state[11];
	state[11] = state[9];
	state[9] = temp;
	//row 3: shift 3 right
	temp = state[12];
	state[12] = state[13];
	state[13] = state[14];
	state[14] = state[15];
	state[15] = temp;
}

void invMixColumns(unsigned char *state) {
	unsigned char column[4];
	unsigned char temp[4];
	register int i;
	// 4 columns
	for (i = 0; i < 4; ++i) {
		// fill column with state elements
		column[0] = state[i];
		column[1] = state[4 + i];
		column[2] = state[8 + i];
		column[3] = state[12 + i];

		// fill temp with column elements
		temp[0] = column[0];
		temp[1] = column[1];
		temp[2] = column[2];
		temp[3] = column[3];

		/*
		The fixed matrix for invmixcolumns is:
		14 11 13 9
		9 14 11 13
		13 9 14 11
		11 13 9 14
		*/
		column[0] = galoisMultiplication(temp[0], 14) ^ galoisMultiplication(temp[1], 11) ^ galoisMultiplication(temp[2], 13) ^ galoisMultiplication(temp[3], 9);
		column[1] = galoisMultiplication(temp[0], 9) ^ galoisMultiplication(temp[1], 14) ^ galoisMultiplication(temp[2], 11) ^ galoisMultiplication(temp[3], 13);
		column[2] = galoisMultiplication(temp[0], 13) ^ galoisMultiplication(temp[1], 9) ^ galoisMultiplication(temp[2], 14) ^ galoisMultiplication(temp[3], 11);
		column[3] = galoisMultiplication(temp[0], 11) ^ galoisMultiplication(temp[1], 13) ^ galoisMultiplication(temp[2], 9) ^ galoisMultiplication(temp[3], 14);

		//put the values in column back in the state
			state[i] = column[0];
			state[4 + i] = column[1];
			state[8 + i] = column[2];
			state[12 + i] = column[3];
	}
}

/*the main function for aes DECRYPTION*/
void aesDecrypt(unsigned char *state, unsigned char *expandedKey, register int nbRounds) {
	unsigned char roundKey[16];

	createARoundKey(expandedKey + 16 * nbRounds, roundKey);
	addRoundKey(state, roundKey);

	register int i = 0;
	for (i = nbRounds - 1; i > 0; --i) {
		createARoundKey(expandedKey + 16 * i, roundKey);
		invShiftRows(state);
		invSubBytes(state);
		addRoundKey(state, roundKey);
		invMixColumns(state);
	}

	createARoundKey(expandedKey, roundKey);
	invShiftRows(state);
	invSubBytes(state);
	addRoundKey(state, roundKey);
}

/*this function recieves input state and the key, then decrypts the input and produces output plaintext*/
unsigned char *decryptBlock(unsigned char *input, unsigned char *key, int keySize, int nbRounds) {
	unsigned char *expandedKey;
	int expandedKeySize = (16 * (nbRounds + 1));
	//128 bit block
	unsigned char block[16];
	//output decrypted block
	unsigned char *output = malloc(16);
	register int i, j;
	//filling the block with input state
	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 4; ++j) {
			block[(i + (j * 4))] = input[(i * 4) + j];
		}
	}

	//condition that checks expandedkey size
	if ((expandedKey = malloc(expandedKeySize)) == NULL) {
		return output;
	}

	//expand the key into a 176, 208, 240 bytes expanded key
	expandKey(expandedKey, key, keySize, expandedKeySize);

	//encrypt block using the expanded key
	aesDecrypt(block, expandedKey, nbRounds);

	register int k, l;
	//filling output state with encrypted block
	for (k = 0; k < 4; ++k) {
		for (l = 0; l < 4; ++l) {
			output[(k * 4) + l] = block[(k + (l * 4))];
		}
	}
	return output;
}

/*main CBC decryption function*/
unsigned char *cbcDecrypt(unsigned char *inputCT, register int ctSize, unsigned char *IV, unsigned char *key, int keySize, int nbRounds) {

	//tempblock acts as input (ciphertext block) and current block, outblock acts as output (plaintext block)
	unsigned char tempBlock[16];
	unsigned char *outBlock;
	//prevblock stores the previous block in the chain
	unsigned char prevBlock[16];
	//initialize output array
	unsigned char *outputPPT = malloc(ctSize);

	//check if array is empty
	if (outputPPT == NULL)
		return outputPPT;

	register int i, j, k, l, m;
	//index for the input ciphertext
	register int index = 0;
	//variable to check if this iteration is the first
	register int isfirst = 1;

	//start cbc Decryption chain
	for (i = 0; i < ctSize; i += 16) {

		//fill temp with current block
		register int tempcounter = 0;
		for (j = index; j < index + 16; ++j) {
			tempBlock[tempcounter] = inputCT[j];
			++tempcounter;
		}

		//(if possible) fill prevblock with previous ciphertext block
		if (isfirst == 0) {
			register int tempcounter2 = 0;
			register int prevIndex = index - 16;
			for (j = prevIndex; j < index; ++j) {
				prevBlock[tempcounter2] = inputCT[j];
				++tempcounter2;
			}
		}

		//decrypt current block
		outBlock = decryptBlock(tempBlock, key, keySize, nbRounds);

		
		if (isfirst != 1) {
		//if not at the start then XOR outblock with the previous cipherblock
		for (l = 0; l < 16; ++l) 
			outBlock[l] ^= prevBlock[l];
		}
		else {
		// if this iteration is at the start of the cbc chain, if yes then XOR outblock with the IV
		for (k = 0; k < 16; ++k)
			outBlock[k] ^= IV[k];

		isfirst = 0;		
		}

		//put decrypted block into outputPPT
		register int tempcounter3 = 0;
		register int finalval = index + 16;
		for (m = index; m < finalval; ++m) {
			outputPPT[m] = outBlock[tempcounter3];
			++tempcounter3;
		}
		free(outBlock);
		//increment index to move to the next block
		index += 16;
	}

	return outputPPT;
}


/****************** DECRYPTION FUNCTIONS END ******************
*/


/*
****************** FILE FUNCTIONS START ******************/

/*Function to get the content of a file and it's size*/
unsigned char *getFileContent(const char *filePath, int *fileSize) {

	// check if file is empty
	if (filePath == NULL) {
		printf("[!] Error when opening the file, file input is empty");
		return NULL;
	}

	//open the file
	FILE *fp = NULL;
	fopen_s(&fp, filePath, "rb");

	if (fp == NULL) {
		printf("[!] Error when opening the file errno: %d\n", errno);
		return NULL;
	}

	//get the file size
	fseek(fp, 0, SEEK_END);
	long fsize = ftell(fp);

	if (fsize <= 0) {
		printf("[!] File size is 0\n");
		return NULL;
	}

	fseek(fp, 0, SEEK_SET);
	*fileSize = fsize;

	//allocate a buffer with the size of the file
	unsigned char *fContent = malloc(fsize);

	//read the content of the file to that buffer and return it
	fread(fContent, fsize, 1, fp);

	fclose(fp);

	return fContent;
}

/*Function that outputs the result into a file*/
bool writeToFile(char *filePath, unsigned char *fileContent, int fileSize) {

	FILE *fp = NULL;
	fopen_s(&fp, filePath, "wb");

	if (fp == NULL) {
		printf("\n [!] Error when opening to write at path: %s\n", filePath);
		return false;
	}

	//write the content to the file with fwrite
	int result = fwrite(fileContent, 1, fileSize, fp);

	//check if writing was successful using result
	if (result != fileSize) {
		printf("\n [!] Error when writing to file at path: %s\n", filePath);
		fclose(fp);
		return false;
	}

	fclose(fp);
	return true;
}

/******************	FILE FUNCTIONS END ******************
*/


/*Function to convert hex key and hex iv to string*/
unsigned char *hexToString(unsigned char *hexString) {
	register int outputLength = strlen(hexString)/2;
	unsigned char *output = malloc(outputLength);

	//the loop goes through every 2 inputs (hex) then converts it to 1 char
	register int i;
	for (i = 0; i < outputLength; ++i) 
		sscanf_s(hexString + (i * 2), "%2hhx", &output[i]);

	return output;
}

/*Function to check te key and iv length*/
bool is_key_and_iv_length_valid(unsigned char *key, int keySize, unsigned char *ivHex) {
	register int keyLength = keySize * 2;
	if (strlen(key) != keyLength) {
		printf("[!] Key is incorrect length. Please input %d byte key. \n", keyLength);
		return false;
	}

	if (strlen(ivHex) != 32) {
		printf("[!] IV is incorrect length. Please input 32 byte IV. \n");
		return false;
	}

	return true;
}

/*Function to set key size in bytes*/
int setKeySize(int keySizeInBits) {
	register int res = 0;
	switch(keySizeInBits){
		case 128:
			res = 16;
			break;
		case 192:
			res = 24;
			break;
		case 256:
			res = 32;
			break;
		default:
			printf("[!] Incorrect key size");
			break;
	}
	return res;
}

/*Function to set the number of rounds based on the key size (in bytes)*/
int setNbRounds(int keySize) {
	register int res = 0;
	switch (keySize){
		case 16:
			res = 10;
			break;
		case 24:
			res = 12;
			break;
		case 32:
			res = 14;
			break;
		default:
			printf("[!] Error setting number of rounds");
			break;
	}
	return res;
}



/*main function for the entire program*/
int main(int argc, char *argv[]) {

	// for timing my code's performance 
	struct timeval t1, t2;
	gettimeofday(&t1, NULL);

	//check if argc = correct number of arguments entered by the user
	if (argc != 7) {
		printf("[!] Incorrect number of arguments, please input: [executable] [(encrypt or decrypt) command] [key size in bits (128 or 192 or 256)] [key] [IV] [input file path] [output file path]");
		return 0;
	}

	// store command in variable
	unsigned char *cmd = argv[1];

	// the cipher key size
	int keySizeInBits = atoi(argv[2]);
	int keySize = setKeySize(keySizeInBits);

	if (keySize == 0)
		return 0;

	// the number of rounds
	int nbRounds = setNbRounds(keySize);

	if (nbRounds == 0)
		return 0;

	// the key in hex
	unsigned char *hexKey = argv[3];

	// the IV in hex
	unsigned char *ivHex = argv[4];

	if (!is_key_and_iv_length_valid(hexKey, keySize, ivHex))
		return 0;

	// the cipher key in string
	unsigned char *key = hexToString(hexKey);
	// the IV in string
	unsigned char *iv = hexToString(ivHex);

	// the output
	unsigned char *outputFile;

	// store input and output file paths in variables
	unsigned char *inputFilePath = argv[5];
	unsigned char *outputFilePath = argv[6];

	int fileSize = 0;
	// fill input array with the target file's content
	unsigned char *inputFile = getFileContent(inputFilePath, &fileSize);

	if (inputFile == NULL) {
		printf("\n [!] Error input file is empty!");
		return 0;
	}

	// if user chose "encrypt" then do encryption steps, if user chose "decrypt" then do decryption steps. If user chose neither then show error message and exit program
	if (_stricmp("encrypt", cmd) == 0) {
		// (can also use strcasecmp if your compiler supports it)
		
		// Padding
		int paddedPtSize = 0;
		unsigned char *paddedPT = pkcs7Pad(inputFile, fileSize, &paddedPtSize);

		// AES CBC encryption
		outputFile = cbcEncrypt(paddedPT, paddedPtSize, iv, key, keySize, nbRounds);

		// Writing the output of encryption to a file
		writeToFile(outputFilePath, outputFile, paddedPtSize);
	}
	else if (_stricmp("decrypt", cmd) == 0) {
		// (can also use strcasecmp if your compiler supports it)
		
		// AES Decryption
		outputFile = cbcDecrypt(inputFile, fileSize, iv, key, keySize, nbRounds);

		// Unpadding
		int unpaddedPtSize = 0;
		unsigned char *unpaddedPT = pkcs7Unpad(outputFile, fileSize, &unpaddedPtSize);

		// Write the output of decryption and unpadding to a file
		writeToFile(outputFilePath, unpaddedPT, unpaddedPtSize);
	}
	else {
		printf("\n [!] Please enter valid command (encrypt or decrypt)");
	}
	
	// for printing how long the code took to perform (in seconds)
	gettimeofday(&t2, NULL);
	double elapsedTime = (t2.tv_sec - t1.tv_sec) + ((t2.tv_usec - t1.tv_usec)/1000000.0);
    printf("%f seconds\n", elapsedTime);

	return 0;
}
