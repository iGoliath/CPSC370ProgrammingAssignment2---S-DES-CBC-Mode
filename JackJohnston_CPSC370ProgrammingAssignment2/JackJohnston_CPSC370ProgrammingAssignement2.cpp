#include <iostream>
#include <string>
using namespace std;

const string S1Box[16] = { "101", "010", "001", "110", "011", "100", "111", "000", "001", "100", "110", "010", "000", "111", "101", "011" };
const string S2Box[16] = { "100", "000", "110", "101", "111", "001", "011", "010", "101", "011", "000", "111", "110", "010", "001", "100"};
void DESEncrypt(int* text, int* key, int Encrpyted[]);
void DESDecrypt(int* text, int* key, int Decrypted[]);
void DESEncrypt2(int* text, int* key, int Encrpyted[]);
void DESDecrypt2(int* text, int* key, int Decrypted[]);


int main() {
	int text[12];
	int key[9];
	string textIn;
	cout << "Please enter the text in binary you wish to encrypt/decrypt: ";
	getline(cin, textIn, '\n');
	for (int i = 0; i <= 11; i++) {
		text[i] = stoi(textIn.substr(i, 1));
	}
	cout << "Please enter the given key value: ";
	getline(cin, textIn, '\n');
	for (int i = 0; i <= 8; i++) {
		key[i] = stoi(textIn.substr(i, 1));
	}

	/*int Encrypted[12];
DESEncrypt(text, key, Encrypted);

cout << "Cyphertext is: ";
for (int i = 0; i < 12; i++)
	cout << Encrypted[i];

int Decrypted[12];
DESDecrypt(Encrypted, key, Decrypted);

cout << "\n\nPlaintext is: ";
for (int i = 0; i < 12; i++)
	cout << Decrypted[i]; */

	int encrypt2[12];
	DESEncrypt(text, key, encrypt2);
	DESEncrypt2(encrypt2, key, encrypt2);
	cout << "\n\nTwo rounds: \n";
	for (int i = 0; i < 6; i++)
		cout << encrypt2[i+6];
	for (int i = 0; i < 6; i++)
		cout << encrypt2[i];

	int decrypt2[12];
	DESDecrypt(encrypt2, key, decrypt2);
	DESDecrypt2(decrypt2, key, decrypt2);
	cout << "\n\nTwo rounds: \n";
	for (int i = 0; i < 12; i++)
		cout << decrypt2[i];

	
}

void DESEncrypt(int* text, int* key, int Encrypted[]) {
	//Initialize Ki-1 Values, Li-1 and Ri-1 Values, and Li; Values;
	int KeyOne[8] = { key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7] };
	int LZero[6] = { text[0], text[1], text[2], text[3], text[4], text[5] };
	int RZero[6] = { text[6], text[7], text[8], text[9], text[10], text[11] };
	int LOne[6] = { RZero[0], RZero[1], RZero[2], RZero[3], RZero[4], RZero[5] };

	//Expansion Of Ri-1;
	int RZeroExpanded[8] = { RZero[0], RZero[1], RZero[3], RZero[2], RZero[3], RZero[2], RZero[4], RZero[5] };

	//Expansion of Ri-1 XOR Ki-1;
	int ExpandedModKey[8];
	for (int i = 0; i < 8; i++) {
		if (RZeroExpanded[i] == KeyOne[i]) {
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

	for (int i = 0; i < 6; i++)
		cout << LOne[i];
	cout << "\t\t";
	for (int i = 0; i < 6; i++)
		cout << ROne[i];
}

void DESEncrypt2(int* text, int* key, int Encrypted[]) {
	//Initialize Ki-1 Values, Li-1 and Ri-1 Values, and Li; Values;
	int KeyOne[8] = { key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8]};
	int LZero[6] = { text[0], text[1], text[2], text[3], text[4], text[5] };
	int RZero[6] = { text[6], text[7], text[8], text[9], text[10], text[11] };
	int LOne[6] = { RZero[0], RZero[1], RZero[2], RZero[3], RZero[4], RZero[5] };

	//Expansion Of Ri-1;
	int RZeroExpanded[8] = { RZero[0], RZero[1], RZero[3], RZero[2], RZero[3], RZero[2], RZero[4], RZero[5] };

	//Expansion of Ri-1 XOR Ki-1;
	int ExpandedModKey[8];
	for (int i = 0; i < 8; i++) {
		if (RZeroExpanded[i] == KeyOne[i]) {
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

	for (int i = 0; i < 6; i++)
		cout << LOne[i];
	cout << "\t\t";
	for (int i = 0; i < 6; i++)
		cout << ROne[i];
}

void DESDecrypt(int* text, int* key, int Decrypted[]) {
	//Initialize Ki Values, Li and Ri Values, and Ri-1; Values;
	int KeyOne[8] = {  key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8]};
	int LOne[6] = { text[0], text[1], text[2], text[3], text[4], text[5] };
	int ROne[6] = { text[6], text[7], text[8], text[9], text[10], text[11] };
	int RZero[6] = { LOne[0], LOne[1], LOne[2], LOne[3], LOne[4], LOne[5] };

	//Expansion Of Ri-1;
	int RZeroExpanded[8] = { RZero[0], RZero[1], RZero[3], RZero[2], RZero[3], RZero[2], RZero[4], RZero[5] };

	//Expansion of Ri-1 XOR Ki;
	int ExpandedModKey[8];
	for (int i = 0; i < 8; i++) {
		if (RZeroExpanded[i] == KeyOne[i]) {
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

void DESDecrypt2(int* text, int* key, int Decrypted[]) {
	//Initialize Ki Values, Li and Ri Values, and Ri-1; Values;
	int KeyOne[8] = {  key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],};
	int LOne[6] = { text[0], text[1], text[2], text[3], text[4], text[5] };
	int ROne[6] = { text[6], text[7], text[8], text[9], text[10], text[11] };
	int RZero[6] = { LOne[0], LOne[1], LOne[2], LOne[3], LOne[4], LOne[5] };

	//Expansion Of Ri-1;
	int RZeroExpanded[8] = { RZero[0], RZero[1], RZero[3], RZero[2], RZero[3], RZero[2], RZero[4], RZero[5] };

	//Expansion of Ri-1 XOR Ki;
	int ExpandedModKey[8];
	for (int i = 0; i < 8; i++) {
		if (RZeroExpanded[i] == KeyOne[i]) {
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
