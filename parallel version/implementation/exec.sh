make rebuild

for i in {0..4}
do
   
   ./run 1, $((2**(i+5)))

done

for i in {0..4}
do
   
   ./run $((4+(4*i))), 512
done

for i in {0..15}
do
   
   ./run $((2**(i+5))), 512

done
echo "Execution finished and data saved successfully"
