# What is this?

x64emulator is a way to quickly analyze a given .o file and see what it may return with some given values.

This is more aimed at trying to reverse engineer a specific function given in the .o format.

# How do I use it?

Download and modify to your liking and use "cargo run" or "cargo build".

To use the example in tests,
``cargo run tests\absdiff.o 3 4``
