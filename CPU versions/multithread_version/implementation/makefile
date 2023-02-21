CC = g++
LFLAGS = -Wall -pthread -std=c++14 -lpthread
CFLAGS = -c -Wall 

all: run.exe 

run.exe: sequential_with_threads.o
	$(CC) sequential_with_threads.o $(LFLAGS) -o run.exe 

sequential.o: 
	$(CC) $(CFLAGS) sequential_with_threads.cpp -o sequential_with_threads.o

clean:
	rm *.o run.exe

rebuild: clean all
