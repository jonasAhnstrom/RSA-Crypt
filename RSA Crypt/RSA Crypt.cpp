// RSA Crypt.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "math.h"
#include <vector>

using namespace std;

typedef struct {
	vector<int> K;
	vector<int> M;
} Message;

typedef struct {
	unsigned long long n = 0;
	unsigned long long e = 0;
} PublicKey;

typedef struct {
	unsigned long long n = 0;
	unsigned long long d = 0;
} PrivateKey;

// C function for extended Euclidean Algorithm
int gcdExtended(long long a, long long b, long long *x, long long *y)
{
	// Base Case
	if (a == 0)
	{
		*x = 0;
		*y = 1;
		return b;
	}

	long long x1, y1; // To store results of recursive call
	long long gcd = gcdExtended(b%a, a, &x1, &y1);

	// Update x and y using results of recursive
	// call
	*x = y1 - (b / a) * x1;
	*y = x1;

	return gcd;
}

Message decrypt(Message m, PrivateKey privK)
{
	for (size_t i = 0; i < (m.K.size()); i++)
	{
		m.M[i] = m.K[i];
	}
	return m;
}

PrivateKey crack(PrivateKey privK, PublicKey pubK)
{
	unsigned long long n = pubK.n;
	unsigned long long e = pubK.e;

	long long nSqr = floor(sqrt(n));

	while (fmod(n, nSqr) != 0) {
		nSqr--;
		if (nSqr % 2 != 1) {
			nSqr--;
		}
	}
	unsigned long long p = nSqr;
	unsigned long long q = n / nSqr;

	long long r = (p - 1)*(q - 1);

	long long x, y;
	gcdExtended(e, r, &x, &y);
	privK.d = x;

	return privK;
}

int main()
{
	PublicKey pubK;
	pubK.n = 225481;
	pubK.e = 31;

	PrivateKey privK;
	privK.n = 225481;

	vector<int> Ke = { 162022,173841,21220,148202,186791,208649,26238,114928,81193,148202,87071,153402,81193,162571,100943,148202,119009,216925,81193,100943,61689,208649,26238,27023,119294,130756,148202,119009,14195,162571,148202,162571,216925,21220,153402,67061,102531,21220,162571 };

	Message m;
	m.K = Ke;

	/*publicKey pubK;
	pubK.n = 10142789312725007;
	pubK.e = 5;

	privateKey privK;
	privK.n = 10142789312725007;*/

	privK = crack(privK, pubK);

	getchar();
	return 0;
}

