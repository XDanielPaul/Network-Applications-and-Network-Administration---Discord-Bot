all: isabot.cpp
	g++ -o  isabot isabot.cpp -lssl -lcrypto