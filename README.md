# Cache Simulator: CMSC 15400 Project
This project involves a cache *simulator*, not a real cache on a computer’s CPU, but a made-up cache that is implemented in software. The cache simulator implements a write-allocate policy for write misses and evicts lines based on LRU.

### Reference Trace Files
The cache is assessed according to sequences of memory references from real programs, which are “replayed against” the cache simulator. The sequence of memory references are stored in *reference trace files*, which are contained in the `traces` subdirectory. The trace files are generated by a Linux program called `valgrind`. For example, typing
```
linux> valgrind --log-fd=1 --tool=lackey -v --trace-mem=yes ls -l
```
on the command line runs the executable program `ls -l`, captures a trace of each of its memory accesses in the order they occur, and prints them to `stdout`.

`valgrind` memory traces have the following form:
```
I 0400d7d4,8
 M 0421c7f0,4
 L 04f6b868,8
 S 7ff0005c8,8
```
Each line denotes one or two memory accesses. The format of each line is
```
[space]operation address,size
```
The *operation* field denotes the type of memory access: `I` denotes an instruction load, `L` a data load, `S` a data store, and `M` a data modify (i.e., a data load followed by a data store). The *address* field specifies a 64-bit hexadecimal memory address. The *size* field specifies the number of bytes accessed by the operation.

## Getting Started
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. Have fun!

### Run
1. Clone this repo into your folder of choice.
    ```
    $ git clone https://github.com/jackandthebean/csim.git
    ```
2. Change directories.
    ```
    $ cd csim
    ```
3. Compile the program.
    ```
    $ make
    ```
4. Run the program:
    ```
    $ ./csim
    Usage: ./csim [-hv] -s <num> -E <num> -b <num> -t <file>
    Options:
      -h         Print this help message.
      -v         Optional verbose flag.
      -s <num>   Number of set index bits.
      -E <num>   Number of lines per set.
      -b <num>   Number of block offset bits.
      -t <file>  Trace file.

    Examples:
      $ ./csim -s 4 -E 1 -b 4 -t traces/yi.trace
      $ ./csim -v -s 8 -E 2 -b 4 -t traces/yi.trace
    ```

## Built With
* [Atom](https://atom.io/) – open-source text editor
* [GCC](https://gcc.gnu.org/) – C compiler
