make rebuild

for j in {1..10}
do
   echo "****************************************** Iteration Number $j ****************************************************"

   # cases where we use only a SM (streaming multiprocessor)
   for i in {0..4}
   do
      
      ./run 1, $((2**(i+5)))

   done

   # cases where we use more that a single SM, until we reach the maximum (5 SM)
   for i in {2..5}
   do
      
      ./run $i, 512
   done

   # cases where we use the maximum number of concurrently threads  
   for i in {2..4}
   do
      
      ./run $((5*i)), 512
   done

   # cases where we increase the number of blocks and in this way the total number of thread
   for i in {0..15}
   do
      
      ./run $((2**(i+5))), 512

   done

done
echo "Execution finished and data saved successfully"
