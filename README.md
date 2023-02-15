# Parallelized Brute Force Attack on AES-256 Key using Cuda-C

University project for **Computer Architecture** course (MSc Computer Engineering at University of Pisa, A.Y. 2022-23)

The aim of this project is to develop and analyze the parallelization of a Brute Force Attack on the AES 256 encryption algorithm. 
In particular, what we want to analyze is: 
- The performance comparison between the first parallelized version and the sequential version. 
- The optimizations between the different parallelized versions. 

The first parallelized version was implemented by exploiting the CPU multithreading, in C++. 
While the subsequent parallel versions were developed in order to be executed on the GPU, through implementation in CUDA-C. 

# How to run
## CPU Versions 
- Select which version (sequential or multithreaded) you want to execute and then compile using the commands inside the makefiles. 
- Run the generated executable. 
## GPU Versions 
- Select which version (before or after the NVIDIA Nsight Compute Optimization) you want to execute and then compile using the commands inside the makefiles. 
- Run the generated executable, if you chose the version before the optimizations you have to pass as command line arguments first the number of blocks and then the number of threads per block. 

# Structure of the repository 

```
Parallelized-AES-Brute-Force-Attack-with-Cuda
|
├── CPU versions
│   ├── multithread_version
│   ├── sequential_version
│   └── results
|
└── GPU versions
│   ├── optimization after NVIDIA Nsight Compute analysis
│   │   ├── implementation
│   │   └── results
│   ├── optimization before NVIDIA Nsight Compute analysis
│       ├── implementation
│       └── results
│
└── files 
    ├── secret_files
    └── text_files

```

## Authors
- [Tommaso Bertini](https://github.com/tommasobertini)
- [Fabrizio Lanzillo](https://github.com/FabrizioLanzillo)
- [Federico Montini](https://github.com/FedericoMontini98)
