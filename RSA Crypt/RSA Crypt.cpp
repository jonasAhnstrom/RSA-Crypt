// RSA Crypt.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "math.h"
#include <vector>
#include <iostream>

using namespace std;

typedef struct {
	vector<long long> K;
	vector<long long> M;
} Message;

typedef struct {
	unsigned long long n = 0;
	unsigned long long e = 0;
} PublicKey;

typedef struct {
	unsigned long long n = 0;
	unsigned long long d = 0;
} PrivateKey;

typedef struct {
	int p = 0;
	int q = 0;
} Factors;


unsigned long long expBySqu(unsigned long long x, unsigned long long n)
{
	// Base Case
	if (n == 1)
	{
		return x;
	}
	if (n % 2 == 0)
	{
		x = expBySqu(powl(x, 2), (n / 2));
		return x;
	}
	if (n > 2 && n % 2 > 0)
	{
		x = x * expBySqu(powl(x, 2), (n - 1) / 2);
	}
	return x;
}


void decrypt(Message* m, PrivateKey privK)
{
	if (privK.d == 0)
	{
		return;
	}
	if (m->K.size() <= 0)
	{
		return;
	}
	/*
	for (size_t i = 0; i < m.K.size(); i++)
	{
		m.M[i] = (m.M[i] * m.K[i]) % privK.n;

		long long pw = pow(m.K[i], privK.d);
		long long modn = pw % privK.n;

		m.M[i] = expBySqu(m.K[i], privK.d);
	}*/
	m->M.assign(m->K.size(), 1);
	//unsigned long long d = 8114231289041741;
	for (size_t i = 0; i < privK.d; i++)
	{
		for (size_t j = 0; j < m->K.size(); j++)
		{
			m->M[j] = (m->M[j] * m->K[j]) % (long long)privK.n;
		}
	}
}


void encrypt(Message* m, PublicKey pubK)
{
	m->K.assign(m->M.size(), 1);

	for (size_t i = 0; i < (pubK.e); i++)
	{
		for (size_t j = 0; j < m->M.size(); j++)
		{
			m->K[j] = fmod(m->K[j] * (int)m->M[j], pubK.n);
		}
	}
}


// Extended Euclidean Algorithm
// TODO: Fails for big a or b
unsigned long long gcdExtended(unsigned long long a, unsigned long long b, unsigned long long *x, unsigned long long *y)
{
	// Base Case
	if (a == 0)
	{
		*x = 0;
		*y = 1;
		return b;
	}

	unsigned long long x1, y1; // To store results of recursive call
	unsigned long long gcd = gcdExtended(b%a, a, &x1, &y1);

	// Update x and y using results of recursive call
	*x = y1 - (b / a) * x1;
	*y = x1;

	return gcd;
}


PrivateKey crack(PrivateKey privK, PublicKey pubK)
{
	unsigned long long n = pubK.n;
	long long nSqr = floor(sqrt(n));

	while (n % nSqr != 0) {
		nSqr--;
		if (nSqr % 2 != 1) {
			nSqr--;
		}
	}
	unsigned long long p = nSqr;
	unsigned long long q = n / nSqr;
	unsigned long long r = (p - 1)*(q - 1);
	unsigned long long e = pubK.e;
	unsigned long long x, y;
	gcdExtended(e, r, &x, &y);
	privK.d = x;

	return privK;
}


Message newMessage(char* string)
{
	Message m;
	for (size_t i = 0; string[i] != '\0'; i++)
	{
		m.M.push_back(string[i]);
	}
	return m;
}


void printMeassage(Message m, int n)
{
	switch (n)
	{
	case 0:
		for (size_t i = 0; i < m.K.size(); i++)
		{
			printf("%I64d ", m.K[i]);
		};
		break;
	case 1:
		printf("\n\n");
		for (size_t i = 0; i < m.M.size(); i++)
		{
			printf("%c", m.M[i]);
		};
		break;
	default:
		break;
	}
}


int IsPrime(unsigned int number) {
	if (number <= 1) return 0; // zero and one are not prime
	unsigned int i;
	for (i = 2; i*i <= number; i++) {
		if (number % i == 0) return 0;
	}
	return 1;
}


int createKeys(Factors f, PublicKey* pubK, PrivateKey* privK, int e)
{
	if (!IsPrime(e))
	{
		return 0;
	}
	pubK->n = f.p * f.q;
	pubK->e = e;

	privK->n = pubK->n;

	int r = (f.p - 1)*(f.q - 1);

	// Find d
	unsigned long long x, y;
	gcdExtended(pubK->e, r, &x, &y);
	privK->d = x;
	return 1;
}


//
// Task 2
//
void task2()
{
	// Keys
	PublicKey pubK;
	pubK.n = 225481;
	pubK.e = 31;
	PrivateKey privK;
	privK.n = pubK.n;
	// Crack key to get 'd'
	privK = crack(privK, pubK);
	
	// Clear text
	Message m = newMessage("Hej från Jonas Ahnström! aka ahjo15ja.");

	// Encrypt message
	encrypt(&m, pubK);

	// Encrypted test message
	//vector<long long> Ke = { 162022,173841,21220,148202,186791,208649,26238,114928,81193,148202,87071,153402,81193,162571,100943,148202,119009,216925,81193,100943,61689,208649,26238,27023,119294,130756,148202,119009,14195,162571,148202,162571,216925,21220,153402,67061,102531,21220,162571 };
	//vector<long long> Ke = { 139940, 208649, 148615, 14195, 148202, 12314, 173841, 186791 };
	//m.K = Ke;

	// Print encrypted message
	printMeassage(m, 0);

	// Decrypt message
	decrypt(&m, privK);

	// Print decrypted message
	printMeassage(m, 1);
}


//
// Task 3
//
void task3()
{
	// Prime numbers p and q
	Factors f;
	f.p = 1999;
	f.q = 3593;

	// Keys
	PublicKey pubK;
	PrivateKey privK;

	if (createKeys(f, &pubK, &privK, 7))
	{
		// Clear text
		Message m = newMessage("Hallojsan!");
		
		// Encrypt message
		encrypt(&m, pubK);

		// Decrypt message
		decrypt(&m, privK);

		// Print decrypted message
		printMeassage(m, 1);
	}
}

//
// Task 4
//
void task4()
{
	// Prime numbers p and q
	Factors f;
	f.p = 71;
	f.q = 59;

	// Keys
	PublicKey pubK;
	PrivateKey privK;
	//privK.d = 1023;

	if (createKeys(f, &pubK, &privK, 127))
	{
		// Clear text
		Message m = newMessage("Uppgift 4 avklarad!");

		// Encrypt message
		encrypt(&m, pubK);

		// Decrypt message
		decrypt(&m, privK);

		// Print decrypted message
		printMeassage(m, 1);
	}
}


int main()
{
	// Set locale settings to what is selected in the environment
	if (!setlocale(LC_ALL, "")) {
		printf("error while setting locale\n");
	}

	// TEST keys; d = 8114231289041741
	/*PublicKey pubK;
	pubK.n = 10142789312725007;
	pubK.e = 5;
	PrivateKey privK;
	privK.n = pubK.n;*/

	//unsigned long long ans = expBySqu(3, 27);

	//
	// Task 1
	//
	// Gratts! Du har nu klarat uppgift 1.

	task2();

	task3();

	task4();

	getchar();
	return 0;
}

