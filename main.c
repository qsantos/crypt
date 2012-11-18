#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "md2.h"
#include "md4.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "cipher.h"

#define TEST(fun,result,test) fun(strlen(test), (uint8_t*)test, sig);for(uint8_t i=0;i<strlen(result)/2;i++)printf("%.2x", sig[i]);printf("\n%s\n", result);
int main()
{
	uint8_t sig[64];
	memset(sig, 0, 64);
	// MD2
	/*
	puts("MD2");
	TEST(MD2, "8350e5a3e24c153df2275c9f80692773", "");
	TEST(MD2, "32ec01ec4a6dac72c0ab96fb34c0b5d1", "a");
	TEST(MD2, "da853b0d3f88d99b30283a69e6ded6bb", "abc");
	TEST(MD2, "ab4f496bfb2a530b219ff33031fe06b0", "message digest");
	TEST(MD2, "4e8ddff3650292ab5a4108c3aa47940b", "abcdefghijklmnopqrstuvwxyz");
	TEST(MD2, "da33def2a42df13975352846c30338cd", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	TEST(MD2, "d5976f79d83d3a0dc9806c3c66f3efd8", "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
	puts("");
	//*/
	
	// MD4
	/*
	puts("MD4");
	TEST(MD4, "31d6cfe0d16ae931b73c59d7e0c089c0", "");
	TEST(MD4, "bde52cb31de33e46245e05fbdbd6fb24", "a");
	TEST(MD4, "a448017aaf21d8525fc10ae87aa6729d", "abc");
	TEST(MD4, "d9130a8164549fe818874806e1c7014b", "message digest");
	TEST(MD4, "d79e1c308aa5bbcdeea8ed63df412da9", "abcdefghijklmnopqrstuvwxyz");
	TEST(MD4, "043f8582f241db351ce627e153e7f0e4", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	TEST(MD4, "e33b4ddc9c38f2199c3e7b164fcc0536", "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
	puts("");
	//*/
	
	// MD5
	/*
	puts("MD5");
	TEST(MD5, "d41d8cd98f00b204e9800998ecf8427e", "");
	TEST(MD5, "0cc175b9c0f1b6a831c399e269772661", "a");
	TEST(MD5, "900150983cd24fb0d6963f7d28e17f72", "abc");
	TEST(MD5, "f96b697d7cb7938d525a2f31aaf161d0", "message digest");
	TEST(MD5, "c3fcd3d76192e4007dfb496cca67e13b", "abcdefghijklmnopqrstuvwxyz");
	TEST(MD5, "d174ab98d277d9f5a5611c2c9f419d9f", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	TEST(MD5, "57edf4a22be3c955ac49da2e2107b67a", "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
	puts("");
	//*/
	
	// SHA-1
	/*
	puts("SHA1");
	TEST(SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", "");
	TEST(SHA1, "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", "a");
	TEST(SHA1, "a9993e364706816aba3e25717850c26c9cd0d89d", "abc");
	TEST(SHA1, "c12252ceda8be8994d5fa0290a47231c1d16aae3", "message digest");
	TEST(SHA1, "32d10c7b8cf96570ca04ce37f2a19d84240d3a89", "abcdefghijklmnopqrstuvwxyz");
	TEST(SHA1, "761c457bf73b14d27e9e9265c46f4b4dda11f940", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	TEST(SHA1, "50abf5706a150990a08b2c5ea40fa0e585554732", "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
	puts("");
	//*/
	
	// SHA-256
	/*
	puts("SHA256");
	TEST(SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "");
	TEST(SHA256, "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "a");
	TEST(SHA256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc");
	TEST(SHA256, "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650", "message digest");
	TEST(SHA256, "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73", "abcdefghijklmnopqrstuvwxyz");
	TEST(SHA256, "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	TEST(SHA256, "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e", "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
	puts("");
	//*/
	
	// SHA-224
	/*
	TEST(SHA224, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", "");
	TEST(SHA224, "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5", "a");
	TEST(SHA224, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", "abc");
	TEST(SHA224, "2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb", "message digest");
	TEST(SHA224, "45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2", "abcdefghijklmnopqrstuvwxyz");
	TEST(SHA224, "bff72b4fcb7d75e5632900ac5f90d219e05e97a7bde72e740db393d9", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	TEST(SHA224, "b50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046e", "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
	//*/
	
	// SHA-512
	/*
	TEST(SHA512, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "");
	TEST(SHA512, "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75", "a");
	TEST(SHA512, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", "abc");
	TEST(SHA512, "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c", "message digest");
	TEST(SHA512, "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1", "abcdefghijklmnopqrstuvwxyz");
	TEST(SHA512, "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	TEST(SHA512, "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843", "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
	//*/
	
	// SHA-384
	/*
	TEST(SHA384, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", "");
	TEST(SHA384, "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31", "a");
	TEST(SHA384, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", "abc");
	TEST(SHA384, "473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5", "message digest");
	TEST(SHA384, "feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4", "abcdefghijklmnopqrstuvwxyz");
	TEST(SHA384, "1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	TEST(SHA384, "b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026", "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
	//*/
	
	// DES
	/*
#define MSG_LEN 8
#define CIP_LEN MSG_LEN + 7-((MSG_LEN-1) % 8)
	uint8_t mode = CIPHER_ALGO_DES | CIPHER_MODE_ECB;
	const uint8_t* R = (const uint8_t*) "\x81\x02\x03\x04\xAB\xCD\xEF\x12";
	const uint8_t* K = (const uint8_t*) "\x01\x02\x03\x04\x45\x23\x12\x78";
	const uint8_t* I = (const uint8_t*) "\x34\x42\x42\x42\x17\x17\x42\x42";
	//for (uint8_t i = 0; i < MSG_LEN; i++)
	//	printf("%.2X", R[i]);
	//putchar('\n');
	
	uint8_t O1[CIP_LEN];
	Crypt(O1, R, MSG_LEN, mode, K, I);
	//for (uint8_t i = 0; i < CIP_LEN; i++)
	//	printf("%.2X", O1[i]);
	//putchar('\n');
	
	uint8_t O2[MSG_LEN];
	Decrypt(O2, O1, CIP_LEN, mode, K, I);
	//for (uint8_t i = 0; i < MSG_LEN; i++)
	//	printf("%.2X", O2[i]);
	//putchar('\n');
	*/
	
	// Benchmarks
	/*
#define DIGEST_STDIN(alg) \
	uint8_t buffer[1024]; \
	alg##ctx* ctx = alg##_new(); \
	while (!feof(stdin)) \
	{ \
		int len = fread(buffer, 1, sizeof(buffer), stdin); \
		alg##_push(ctx, len, buffer); \
	} \
	alg##_hash(ctx, buffer);
	
	DIGEST_STDIN(SHA512);
	for (uint8_t i = 0; i < 20; i++)
		printf("%.2x", buffer[i]);
	putchar('\n');
	//*/
	
	return 0;
}
