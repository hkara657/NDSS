all: zp-server ecc-server zp-client ecc-client

zp-server: dh-server.cpp
	g++ dh-server.cpp -o zp-server -lcrypto

ecc-server: ecc-server.cpp
	g++ -O3 ecc-server.cpp -o ecc-server -std=c++11 -lcrypto

zp-client: dh-client.cpp
	g++ dh-client.cpp -o zp-client -lcrypto

ecc-client: ecc-client.cpp
	g++ -O3 ecc-client.cpp -o ecc-client -std=c++11 -lcrypto

