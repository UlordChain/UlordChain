[sunl@localhost PoW]$ ./PoW hashcat
**************************** Correctness test (One way function) ****************************
Test message: hashcat
00 SHA3-256          	d60fcf6585da4e17224f58858970f0ed5ab042c3916b76b0b828e62eaf636cbd
01 SHA1              	125d38130752be6f1b710b727768294d0e6a277b79cde0eea011a8458fde3cbe
02 SHA256            	127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935
03 SHA512            	b67061ba08c087b396df4f47661bfe098e7de3d4c7b7de51914064f32a36eabe
04 Whirlpool         	aefc3088ab874844b539c32c008f0f4fac8d63ddb21f441787f82abba85739d7
05 RIPEMD-160        	6fc8a2f9a021da2b71a9c8ce85586082467f7eb600d9c268807e206d92006a6b
06 BLAKE2s(256bits)  	2c719b484789ad5f6fc1739012182169b25484af156adc91d4f64f72400e574a
07 AES(128bits)      	0d1630bf9b56c515587d12015e1215daa5e50b19e46e4bff3cff2c90a1b1b586
08 DES               	b1f4734a9c6f4e275212914931d4d37e104479d43b0f784846e5983cff26b355
09 RC4               	4e37223ef35eb9a548e18daf69fb4ab62eccdd9d12d5456e4e2de42421017e07
10 Camellia(128bits) 	b9ac51b5b658cc157b968a30ea5195d24df7490853de5fb6de1bd8d95bd5ddf4
11 CRC32             	27dc803c0dfecf954abff2666caa0bc7329ab0bf9f8ae065b6eda1fe98befb37
12 HMAC(MD5)         	3bd73ff59cd127e7ace5db20f6fbaf5d27c2ef5510bcc2faa2b00f5a5741c7b6
13 GOST R 34.11-94   	df226c2c6dcb1d995c0299a33a084b201544293c31fc3d279530121d36bbcea9
14 HAVAL-256/5       	72f72ddb75c084e6bfe4b939299c55f3d1c1d79f5ec5a9cc3470e0fa56914e9a
15 Skein-512(256bits)	45e91567c3263a5fb2bcb4a4e403c3b776c087be7176335b2b4d97d3ef47614c
*********************************************************************************************
************************************************* Performance test (One way function) *************************************************
   Algorithm                    1           4           8          12          16          20          24          32          48          64
00 SHA3-256          	 1010 Kps    4041 Kps    8046 Kps   11692 Kps   10545 Kps   10355 Kps   11052 Kps   11581 Kps   11463 Kps   11808 Kps   
01 SHA1              	 2379 Kps    9252 Kps   18560 Kps   24549 Kps   22240 Kps   25991 Kps   25987 Kps   25409 Kps   25145 Kps   25985 Kps   
02 SHA256            	 2810 Kps   11132 Kps   19997 Kps   26516 Kps   27441 Kps   31146 Kps   29642 Kps   30162 Kps   30436 Kps   30521 Kps   
03 SHA512            	 1796 Kps    7134 Kps   14262 Kps   13542 Kps   17585 Kps   20353 Kps   20074 Kps   19056 Kps   20440 Kps   20568 Kps   
04 Whirlpool         	 1121 Kps    4468 Kps    8909 Kps   12669 Kps   11428 Kps   11432 Kps   12172 Kps   13057 Kps   13018 Kps   12556 Kps   
05 RIPEMD-160        	 1002 Kps    3993 Kps    7968 Kps   11842 Kps    9302 Kps   11164 Kps   11462 Kps   10852 Kps   11609 Kps   11784 Kps   
06 BLAKE2s(256bits)  	 3361 Kps   13382 Kps   26705 Kps   35174 Kps   30524 Kps   33288 Kps   35013 Kps   38655 Kps   38455 Kps   37948 Kps   
07 AES(128bits)      	  921 Kps    3674 Kps    7320 Kps    9397 Kps    9777 Kps    9868 Kps   10219 Kps   10292 Kps   10666 Kps   10767 Kps   
08 DES               	  657 Kps    2618 Kps    5228 Kps    7751 Kps    6795 Kps    7389 Kps    7085 Kps    7432 Kps    7604 Kps    7723 Kps   
09 RC4               	  754 Kps    3012 Kps    6013 Kps    8974 Kps    7760 Kps    8058 Kps    8592 Kps    8429 Kps    8801 Kps    8870 Kps   
10 Camellia(128bits) 	 1075 Kps    4282 Kps    8544 Kps   12605 Kps   10972 Kps   12147 Kps   11262 Kps   12375 Kps   12316 Kps   12300 Kps   
11 CRC32             	 2185 Kps    8701 Kps   17445 Kps   24501 Kps   19951 Kps   20649 Kps   25113 Kps   24152 Kps   25284 Kps   24897 Kps   
12 HMAC(MD5)         	  481 Kps    1042 Kps    1916 Kps    2782 Kps    2960 Kps    3315 Kps    3604 Kps    3972 Kps    4243 Kps    4656 Kps   
13 GOST R 34.11-94   	  372 Kps    1485 Kps    2974 Kps    4430 Kps    3965 Kps    4130 Kps    4162 Kps    4362 Kps    4359 Kps    4383 Kps   
14 HAVAL-256/5       	 1617 Kps    6464 Kps   12858 Kps   18313 Kps   16855 Kps   17738 Kps   17991 Kps   17358 Kps   17705 Kps   18522 Kps   
15 Skein-512(256bits)	 2319 Kps    9237 Kps   18491 Kps   19833 Kps   24235 Kps   22065 Kps   26723 Kps   25705 Kps   25774 Kps   25915 Kps   
***************************************************************************************************************************************
****************************** Correctness test (PoW function) ******************************
Test message: hashcat
PoW               	224afc7c2525c33eb428167c1fa1b2fa7cf90576ad875064d9948276218a3a75
*********************************************************************************************
*************************************************** Performance test (PoW function) ***************************************************
   Algorithm                    1           4           8          12          16          20          24          32          48          64
00 PoW               	   80 bps     318 bps     635 bps     951 bps     911 bps     947 bps     920 bps     900 bps     807 bps     788 bps   
***************************************************************************************************************************************