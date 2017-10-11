/* Copyright (C) 2012,2013 IBM Corp.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/* Test_General.cpp - A general test program that uses a mix of operations over four ciphertexts.
 */

#include "FHE.h"

int main(int argc, char **argv)
{
	/*** BEGIN INITIALIZATION ***/
	long m = 0;                   // Specific modulus
	long p = 1021;                // Plaintext base [default=2], should be a prime number
	long r = 1;                   // Lifting [default=1]
	long L = 16;                  // Number of levels in the modulus chain [default=heuristic]
	long c = 3;                   // Number of columns in key-switching matrix [default=2]
	long w = 64;                  // Hamming weight of secret key
	long d = 0;                   // Degree of the field extension [default=1]
	long k = 128;                 // Security parameter [default=80] 
    long s = 0;                   // Minimum number of slots [default=0]

	std::cout << "Finding m... " << std::flush;
	m = FindM(k, L, c, p, d, s, 0);                            // Find a value for m given the specified values
	std::cout << "m = " << m << std::endl;
	
	std::cout << "Initializing context... " << std::flush;
	FHEcontext context(m, p, r); 	                        // Initialize context
	buildModChain(context, L, c);                           // Modify the context, adding primes to the modulus chain
	std::cout << "OK!" << std::endl;

	std::cout << "Creating polynomial... " << std::flush;
	ZZX G =  context.alMod.getFactorsOverZZ()[0];                // Creates the polynomial used to encrypt the data
	std::cout << "OK!" << std::endl;

	std::cout << "Generating keys... " << std::flush;
	FHESecKey secretKey(context);                           // Construct a secret key structure
	const FHEPubKey& publicKey = secretKey;                 // An "upcast": FHESecKey is a subclass of FHEPubKey
	secretKey.GenSecKey(w);                                 // Actually generate a secret key with Hamming weight w
	std::cout << "OK!" << std::endl;
	/*** END INITIALIZATION ***/
	
	int Kewords[] = {1,2,3,
			 11,12,13,21,22,23,31,32,33,
			  111,112,113,121,122,123,131,132,133,
			  211,212,213,221,222,223,231,232,233,
			  311,312,313,321,322,323,331,332,333,1111,2321,3132 };

	Ctxt searchterm(publicKey);                // Initialize the first ciphertext (ctx1) using publicKey
	Ctxt mask(publicKey);                // Initialize the first ciphertext (ctx2) using publicKey

	int word;
	int len;
	int index;

	cout << "Enter the searchterm : \n";
	cin >> word;

	cout << "Enter the length : \n";
	cin >> len;

	cout << "Enter the index : \n";
	cin >> index;

	int mask_n =  4*(pow(10,len-index));

	publicKey.Encrypt(searchterm, to_ZZX(word));  // Encrypt the value CAB(312)
	publicKey.Encrypt(mask, to_ZZX(mask_n));  // Encrypt the value mask_n
	
	Ctxt sum = searchterm;                   // Create a ciphertext to hold the sum and initialize it with searchterm
	sum += mask;                       // Perform searchterm + mask

	ZZX ptSum;                           //	Create a plaintext to hold the plaintext of the sum
	secretKey.Decrypt(ptSum, sum);	 // Decrypt the ciphertext ctSum into the plaintext ptSum using secretKey

	std::cout << word << " + " << mask_n << " = " << ptSum[0] << std::endl;
	
	for(int i=0;i<42;i++){
		//cout << "matching\n";
		int key = Kewords[i];
		Ctxt key_e(publicKey);
		publicKey.Encrypt(key_e, to_ZZX(key));
		Ctxt diff = sum;
		diff -= key_e;

		ZZX diff_decr;                           //	Create a plaintext to hold the plaintext of the diff
		secretKey.Decrypt(diff_decr, diff);		 
		int j;
		for(j = 10 ; j < 91 ; j += 10  ){
			Ctxt check(publicKey);
			publicKey.Encrypt(check, to_ZZX(j));
			
			Ctxt isMatch = diff;
			isMatch -= check;

			Ctxt zero(publicKey);
			publicKey.Encrypt(zero, to_ZZX(0));

			ZZX zero_d;                           //	Create a plaintext to hold the plaintext of the sum
			secretKey.Decrypt(zero_d, zero);	 

			ZZX isMatch_d;                           //	Create a plaintext to hold the plaintext of the sum
			secretKey.Decrypt(isMatch_d,isMatch );	 

			//cout <<  isMatch_d[0] << "\n";
			if( zero_d[0] == isMatch_d[0] ) {
				std::cout << key << " " << diff_decr[0] << " accept" << std::endl;
				break;	
			}
		}

		if(j >= 91){
			std::cout << key << " " << diff_decr[0] << " reject" << std::endl;
		}
		
	}
	return 0;
}

