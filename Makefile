all: result.out

result.out: driver.cpp aes.o rsa.o compress.o
	g++ driver.cpp aes.o rsa.o compress.o -o result.out -lssl -lcrypto -lm -lz

aes.o: aes.cpp
	g++ aes.cpp -c -lssl -lcrypto

rsa.o: rsa.cpp
	g++ rsa.cpp -c -lssl -lcrypto

compress.o: compress.cpp
	g++ compress.cpp -lm -lz -c

run_e:
	./result.out encrypt secret.txt encrypted_file rec_public.pem send_private.pem

run_d:
	./result.out decrypt encrypted_file decrypted_file.txt rec_private.pem send_public.pem

keygen:
	openssl genrsa -out rec_private.pem 4096
	openssl rsa -in rec_private.pem -outform PEM -pubout -out rec_public.pem
	openssl genrsa -out send_private.pem 4096
	openssl rsa -in send_private.pem -outform PEM -pubout -out send_public.pem

clean:
	rm -f *.o *.out *.pem encrypted_file.txt decrypted_file.txt
