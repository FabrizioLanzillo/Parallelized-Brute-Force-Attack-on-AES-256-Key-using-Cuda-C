CC = g++
LFLAGS = -Wall -pthread -std=c++14 
CFLAGS = -c -Wall 

all: run.exe 

run.exe: sequential.o
	$(CC) sequential.o $(LFLAGS) -o run.exe 

sequential.o: 
	$(CC) $(CFLAGS) sequential.cpp -o sequential.o

clean:
	rm *.o run.exe results/*.txt

rebuild: clean all
