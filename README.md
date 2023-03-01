# What is this?

x64emulator is a way to quickly analyze a given .o file and see what it may return with some given values.

This is more aimed at trying to reverse engineer a specific function given in the .o format.

# How do I use it?

Download and modify to your liking and use "cargo run" or "cargo build".

To use the example in tests,
``x64emulator.exe absdiff.o 3 4``

The order in which registers are passed over the command line is %rdi, %rsi, %rdx, %rcx, %r8, %r9.

So in the case of, ``x64emulator.exe M1.o 3 4``, %rdi is now 3 and %rsi is 4.

The function you've provided with the .o file will now be emulated with the given arguments.

After emulation is finished, the emulator will spit out the register state at the end of emulation.
The output of the most previous example would be,

```
C:\Users\unknown\Desktop\Programming\x64emulator>cargo run tests\M1.o 3 4      
    Finished dev [unoptimized + debuginfo] target(s) in 0.17s
     Running `target\debug\x64emulator.exe tests\M1.o 3 4`   
RAX : 81
 Binary view: 1010001
RDI : 3
 Binary view: 11
RSI : 0
 Binary view: 0
RDX : 4294967295
 Binary view: 11111111111111111111111111111111
RCX : 0
 Binary view: 0
R8 : 0
 Binary view: 0
R9 : 0
 Binary view: 0
```

Now you can see the effects the function has on the registers and what it returns.

# Emulating arrays

x64emulator can accept one array in each function signature. If your function requires a pointer to an array, you must first tell the emulator through the command line arguments at which address the array should start with `-a`. After which, you provide the array values delimited by a comma with `-v`. An example of an object file which uses this is located in `tests\M3.o`, to emulate this file you'd use...

`x64emulator.exe M3.o 10000 5 -a 10000 -v 5,2,10,3,7`

In the case of the previous example, we are stating set RDI to 10000, RSI to 5, allocate an array at address 10000 with the values 5,2,10,3,7. The function signature looks something like `somefunction(int* myarray, size)`.

If your pointer to the array was located in RSI, RCX, or RDX, you can specify that by doing something such as `x64emulator.exe 0 3 10000 -a 10000 5,2,5`.
An example of a function signature that may have that looks like `somefunc(int random, int size, int* myarray)`. Support for more than one array is planned for future releases.
