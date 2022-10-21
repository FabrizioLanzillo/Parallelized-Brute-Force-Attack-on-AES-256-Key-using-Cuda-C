make clean
make
for i in {1..10}
do
   ./run.exe 8 # 1 byte
   ./run.exe 16 # 2 bytes
   ./run.exe 20 # 2 bytes and 4 bits
   ./run.exe 24 # 3 bytes
   ./run.exe 27 # 3 bytes and 3 bits
   ./run.exe 30 # 3 bytes and 3 bits
   #./run.exe 32 # 4 bytes

done
echo "Execution finished and data saved successfully"