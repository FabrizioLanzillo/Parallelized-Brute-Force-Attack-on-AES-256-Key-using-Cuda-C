make rebuild
make
for i in {1..10}
do      
      ./run.exe 8 8 
      ./run.exe 8 16
      ./run.exe 8 32

      ./run.exe 16 8 # 2 bytes
      ./run.exe 16 16
      ./run.exe 16 32

      ./run.exe 20 8 # 2 bytes and 4 bits
      ./run.exe 20 16
      ./run.exe 20 32

      ./run.exe 24 8 # 3 bytes
      ./run.exe 24 16
      ./run.exe 24 32

      ./run.exe 27 8 # 3 bytes and 3 bits
      ./run.exe 27 16
      ./run.exe 27 32

      ./run.exe 30 8 # 3 bytes and 6 bits
      ./run.exe 30 16
      ./run.exe 30 32

      #./run.exe 32 # 4 bytes
done
echo "Execution finished and data saved successfully"
