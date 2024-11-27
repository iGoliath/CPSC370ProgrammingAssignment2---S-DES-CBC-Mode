/*Jack Johnston
* CPSC370
* jjohnsto11@live.esu.edu
* 11/26/2024
* This program first performs a single round of encryption/decryption using the S-DES cipher.
* Next, it performs two rounds of encryption/decryption using the S-DES cipher. 
* Next, the CBC (Cipher Block Chaining) mode is used in tandem with the S-DES cipher to ecrypt 2 blocks
* of 12-bit plaintext. The resulting ciphertext is then decrypted.
* Finally, two 48-bit plaintexts which differ by 1 bit are encrypted. This displays the avalanche effect
* of the CBC mode, as numerous bits of the new cipher text differs by much more than 1 bit.
*/
#include <iostream>
#include <string>
#include <vector>
using namespace std;

const string S1Box[16] = { "101", "010", "001", "110", "011", "100", "111", "000", "001", "100", "110", "010", "000", "111", "101", "011" };
const string S2Box[16] = { "100", "000", "110", "101", "111", "001", "011", "010", "101", "011", "000", "111", "110", "010", "001", "100"};
void DESEncrypt(int* text, int* key, int Encrpyted[]);
void DESDecrypt(int* text, int* key, int Decrypted[]);
void CBCEncrypt(int* text, int* key, int* IV, vector<int> &results, int rounds);
void CBCDecrypt(int* text, int* key, int* IV, vector<int>& results, int rounds);


int main() {

	cout << "Part I: S-DES\n\nItem #1: 1 Round Encrypt/Decrypt\n\n";

	int key[8] = { 1, 1, 1, 0, 0, 0, 1, 1 };
	int key2[8] = { 1, 1, 0, 0, 0, 1, 1, 1 };
	int Plain[12] = { 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1 };
	int Answer[12];
	cout << "Round 1:\nDecryption:\n";
	DESEncrypt(Plain, key, Answer);
	cout << "Ciphertext (RL) is: ";
	for (int i = 6; i < 12; i++)
		cout << Answer[i];
	for (int i = 0; i < 6; i++)
		cout << Answer[i];
	cout << "\nEncryption:\nPlaintext is: ";
	DESDecrypt(Answer, key, Answer);
	for (int i = 0; i < 12; i++)
		cout << Answer[i];
	cout << "\n\n\nItem #2: 2 Rounds of Encrypt/Decrypt\n\nRound 1: \nEncryption: \nPlaintext (RL) is: ";
	int Plain2[12] = { 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0 };
	DESEncrypt(Plain2, key, Answer);
	DESEncrypt(Answer, key2, Answer);
	for (int i = 6; i < 12; i++)
		cout << Answer[i];
	for (int i = 0; i < 6; i++)
		cout << Answer[i];
	cout << "\nDecryption: ";
	DESDecrypt(Answer, key2, Answer);
	DESDecrypt(Answer, key, Answer);
	for (int i = 0; i < 12; i++)
		cout << Answer[i];

	cout << "\n\n\nPart II: CBC Mode:\n\n1) Encryption/Decryption\nStarting Plaintext P = 100010110101011100100110\n\nC1 = R2L2: ";
	
	int IV[12] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
	int CBCPlain[24] = { 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0 };
	int CBCKey[12] = { 1, 1, 1, 0, 0, 0, 1, 1, 1 };
	vector<int> toReturn;
	CBCEncrypt(CBCPlain, CBCKey, IV, toReturn, 2);

	for (int i = 0; i < 24; i++) {
		if (i == 12)
			cout << "\nC2 = R2L2: ";
		cout << toReturn[i];
	}
	cout << "\nAfter encryption, ciphertext is: ";
	for (int i = 0; i < 24; i++)
		cout << toReturn[i];
	cout << "\n\n";
	int in[24];
	for (int i = 0; i < 6; i++) {
		in[i] = toReturn[i + 6];
	}
	for (int i = 6; i < 12; i++) {
		in[i] = toReturn[i - 6];
	}
	for (int i = 12; i < 18; i++) {
		in[i] = toReturn[i + 6];
	}
	for (int i = 18; i < 24; i++) {
		in[i] = toReturn[i - 6];
	}
	
	vector<int> toReturnagain;
	CBCDecrypt(in, CBCKey, IV, toReturnagain, 2);
	cout << "After decryption, plaintext is: ";
	for (int i = 0; i < 24; i++)
		cout << toReturnagain[i];
		
	cout << "\n\n2) Effect on ciphertext when bit 14 of plaintext is different: \n\n";
	int CBCNewPlain[48] = { 1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0 };
	int CBCNewPlain2[48] = { 1,1,0,0,1,1,0,0,1,1,0,0,1,0,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0 };
	vector<int> CBCAnswer;
	vector<int> CBCAnswer2;
	CBCEncrypt(CBCNewPlain, CBCKey, IV, CBCAnswer, 4);
	cout << "C1 = R2L2 is :";
	for (int i = 0; i < 12; i++)
		cout << CBCAnswer[i];
	cout << "\nC2 = R2L2 is :";
	for (int i = 12; i < 24; i++)
		cout << CBCAnswer[i];
	cout << "\nC3 = R2L2 is :";
	for (int i = 24; i < 36; i++)
		cout << CBCAnswer[i];
	cout << "\nC4 = R2L2 is :";
	for (int i = 36; i < 48; i++)
		cout << CBCAnswer[i];
	cout << "\nCiphertext of the first plaintext is: ";
	for (int i = 0; i < 48; i++)
		cout << CBCAnswer[i];

	CBCEncrypt(CBCNewPlain2, CBCKey, IV, CBCAnswer2, 4);
	cout << "\nC1 = R2L2 is :";
	for (int i = 0; i < 12; i++)
		cout << CBCAnswer2[i];
	cout << "\nC2 = R2L2 is :";
	for (int i = 12; i < 24; i++)
		cout << CBCAnswer2[i];
	cout << "\nC3 = R2L2 is :";
	for (int i = 24; i < 36; i++)
		cout << CBCAnswer2[i];
	cout << "\nC4 = R2L2 is :";
	for (int i = 36; i < 48; i++)
		cout << CBCAnswer2[i];
	cout << "\nCiphertext of the second plaintext is: ";
	for (int i = 0; i < 48; i++)
		cout << CBCAnswer2[i];
}

void DESEncrypt(int* text, int* Key, int Encrypted[]) {
	//Initialize Ki-1 Values, Li-1 and Ri-1 Values, and Li; Values;
	
	int LZero[6] = { text[0], text[1], text[2], text[3], text[4], text[5] };
	int RZero[6] = { text[6], text[7], text[8], text[9], text[10], text[11] };
	int LOne[6] = { RZero[0], RZero[1], RZero[2], RZero[3], RZero[4], RZero[5] };

	//Expansion Of Ri-1;
	int RZeroExpanded[8] = { RZero[0], RZero[1], RZero[3], RZero[2], RZero[3], RZero[2], RZero[4], RZero[5] };

	//Expansion of Ri-1 XOR Ki-1;
	int ExpandedModKey[8];
	for (int i = 0; i < 8; i++) {
		if (RZeroExpanded[i] == Key[i]) {
			ExpandedModKey[i] = 0;
		}
		else
			ExpandedModKey[i] = 1;
	}

	//Find index for S1 Box;
	int S1[4] = { ExpandedModKey[0], ExpandedModKey[1], ExpandedModKey[2], ExpandedModKey[3] };
	int SOne = 0;
	if (S1[0] == 1)
		SOne += 8;
	if (S1[1] == 1)
		SOne += 4;
	if (S1[2] == 1)
		SOne += 2;
	if (S1[3] == 1)
		SOne += 1;

	//Find index for S2 Box;
	int S2[4] = { ExpandedModKey[4], ExpandedModKey[5], ExpandedModKey[6], ExpandedModKey[7] };
	int STwo = 0;
	if (S2[0] == 1)
		STwo += 8;
	if (S2[1] == 1)
		STwo += 4;
	if (S2[2] == 1)
		STwo += 2;
	if (S2[3] == 1)
		STwo += 1;

	//Grab values from S1 and S2 Box;
	string SOneBox = S1Box[SOne];
	string STwoBox = S2Box[STwo];

	int fRiMinus1ModKi[6];

	//Initialize right side of f(Ri-1, Ki);
	int j = 2;
	for (int i = 5; i >=3; i--) {
		fRiMinus1ModKi[i] = (STwoBox[j])-48;
		j--;
	}

	//Initialize left side of (fRi-1, Ki);
	j = 2;
	for (int i = 2; i >= 0; i--) {
		fRiMinus1ModKi[i] = SOneBox[j]-48;
		j--;
	}

	int ROne[6];
	for (int i = 0; i < 6; i++) {
		if (LZero[i] == fRiMinus1ModKi[i]) {
			ROne[i] = 0;
		}
		else
			ROne[i] = 1;
	}

	for (int i = 0; i < 6; i++)
		Encrypted[i] = LOne[i];

	for (int i = 0; i < 6; i++)
		Encrypted[i + 6] = ROne[i];

}


void DESDecrypt(int* text, int* key, int Decrypted[]) {
	//Initialize Ki Values, Li and Ri Values, and Ri-1; Values;
	int LOne[6] = { text[0], text[1], text[2], text[3], text[4], text[5] };
	int ROne[6] = { text[6], text[7], text[8], text[9], text[10], text[11] };
	int RZero[6] = { LOne[0], LOne[1], LOne[2], LOne[3], LOne[4], LOne[5] };

	//Expansion Of Ri-1;
	int RZeroExpanded[8] = { RZero[0], RZero[1], RZero[3], RZero[2], RZero[3], RZero[2], RZero[4], RZero[5] };

	//Expansion of Ri-1 XOR Ki;
	int ExpandedModKey[8];
	for (int i = 0; i < 8; i++) {
		if (RZeroExpanded[i] == key[i]) {
			ExpandedModKey[i] = 0;
		}
		else
			ExpandedModKey[i] = 1;
	}

	//Find index for S1 Box;
	int S1[4] = { ExpandedModKey[0], ExpandedModKey[1], ExpandedModKey[2], ExpandedModKey[3] };
	int SOne = 0;
	if (S1[0] == 1)
		SOne += 8;
	if (S1[1] == 1)
		SOne += 4;
	if (S1[2] == 1)
		SOne += 2;
	if (S1[3] == 1)
		SOne += 1;

	//Find index for S2 Box;
	int S2[4] = { ExpandedModKey[4], ExpandedModKey[5], ExpandedModKey[6], ExpandedModKey[7] };
	int STwo = 0;
	if (S2[0] == 1)
		STwo += 8;
	if (S2[1] == 1)
		STwo += 4;
	if (S2[2] == 1)
		STwo += 2;
	if (S2[3] == 1)
		STwo += 1;

	//Grab values from S1 and S2 Box;
	string SOneBox = S1Box[SOne];
	string STwoBox = S2Box[STwo];

	int fRiMinus1ModKi[6];

	//Initialize right side of f(Ri-1, Ki);
	int j = 2;
	for (int i = 5; i >= 3; i--) {
		fRiMinus1ModKi[i] = (STwoBox[j]) - 48;
		j--;
	}

	//Initialize left side of (fRi-1, Ki);
	j = 2;
	for (int i = 2; i >= 0; i--) {
		fRiMinus1ModKi[i] = SOneBox[j] - 48;
		j--;
	}

	int LZero[6];
	for (int i = 0; i < 6; i++) {
		if (ROne[i] == fRiMinus1ModKi[i]) {
			LZero[i] = 0;
		}
		else
			LZero[i] = 1;
	}


	for (int i = 0; i < 6; i++)
		Decrypted[i] = LZero[i];

	for (int i = 0; i < 6; i++)
		Decrypted[i + 6] = RZero[i];

}

void CBCEncrypt(int* text, int* key, int* IV, vector<int> &results, int rounds) {
	//Initialize the array to store C(i-1). For now it is just the initial vector
	int C[12];
	for (int i = 0; i < 12; i++) {
		C[i] = IV[i];
	}
	int mod[12] = { 0 };
	int useKey[8] = { 0 };
	int temp[6] = { 0 };
	int var;
	for (int i = 0; i < rounds; i++) {
		//Perform the initial XOR of the plaintext and previous ciphertext
		for (int j = 0; j < 12; j++) {
			if (text[j + (i * 12)] != C[j])
				mod[j] = 1;
			else
				mod[j] = 0;
		}
		//Grab K1
		for (int j = 0; j < 8; j++) {
			useKey[j] = key[j];
		}
		DESEncrypt(mod, useKey, C);
		//Grab K2
		for (int j = 1; j < 9; j++) {
			useKey[j - 1] = key[j];
		}
		DESEncrypt(C, useKey, C);
		//Store the ciphertext in the vector in main
		for (int a = 6; a < 12; a++) {
			results.push_back(C[a]);
		}
		for (int a = 0; a < 6; a++) {
			results.push_back(C[a]);
		}
		//Reverse L and R for next step
		for (int i = 0; i < 6; i++) {
			temp[i] = C[i];
			C[i] = C[i + 6];
			C[i + 6] = temp[i];
		}
		
	}

}

void CBCDecrypt(int* text, int* key, int* IV, vector<int>& results, int rounds) {
	int useKey[8];
	int roundText[12];
	int prevRoundText[12] = { 0 };
	int Decrypted[12];
	int Plaintext[12] = { 0 };
	for (int i = 0; i < rounds; i++) {
		//Grab K2
		for (int j = 1; j < 9; j++) {
			useKey[j - 1] = key[j];
		}
		//Grab ciphertext for given round
		for (int j = 0; j < 12; j++) {
			roundText[j] = text[j + (i * 12)];
		}
		DESDecrypt(roundText, useKey, Decrypted);
		//Grab K1
		for (int j = 0; j < 8; j++) {
			useKey[j] = key[j];
		}
		DESDecrypt(Decrypted, useKey, Decrypted);
		//XOR with C(i-1). If i == 0 (first round),
		//the IV is used instead
		for (int j = 0; j < 12; j++) {
			if (i == 0) {
				if (IV[j] != Decrypted[j])
					Plaintext[j] = 1;
			}
			else {
				if (Decrypted[j] != prevRoundText[j])
					Plaintext[j] = 1;
				else
					Plaintext[j] = 0;
			}
		}
		//Save the current round's ciphertext for use in next iteration
		for (int j = 0; j < 6; j++) {
			prevRoundText[j] = roundText[j + 6];
		}
		for (int j = 6; j < 12; j++) {
			prevRoundText[j] = roundText[j - 6];
		}
		//Save plaintext in vector for main
		for (int j = 0; j < 6; j++) {
			results.push_back(Plaintext[j]);
		}
		for (int j = 6; j < 12; j++) {
			results.push_back(Plaintext[j]);
		}
	}
	
}


