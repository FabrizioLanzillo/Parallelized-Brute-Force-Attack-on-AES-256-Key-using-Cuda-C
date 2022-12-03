CC = g++
LFLAGS = -Wall -pthread -std=c++14 -Wno-unknown-pragmas #does not work without lssl 
CFLAGS = -c -Wall 

all: run.exe 

run.exe: ex_aes_solution.o
	$(CC) ex_aes_solution.o $(LFLAGS) -o run.exe 

ex_aes_solution.o: 
	$(CC) $(CFLAGS) ex_aes_solution.cpp -o ex_aes_solution.o

clean:
	rm *.o run.exe ./../files/secret_files/iv.txt ./../files/secret_files/key_aes.txt results/*.txt

rebuild: clean all