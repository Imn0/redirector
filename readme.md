# Redirecotor
Program to redirect other program's stdout, stdin, stderr (like > < 2>) while it's running.

Example use
```
$ ./SomeProgram & 
>> [1] 6204
$ ./redirector 6204 1 out.txt
```
This will redirect stdout of SomeProgram to out.txt.
