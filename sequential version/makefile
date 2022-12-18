CC = g++
LFLAGS = -Wall -pthread -std=c++14 
CFLAGS = -c -Wall 

all: run.exe 

run.exe: ex_aes_solution.o
	$(CC) ex_aes_solution.o $(LFLAGS) -o run.exe 

ex_aes_solution.o: 
	$(CC) $(CFLAGS) ex_aes_solution.cpp -o ex_aes_solution.o

clean:
	rm *.o run.exe results/*.txt

rebuild: clean all
