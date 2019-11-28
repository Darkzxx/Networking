Instruction on building and compiling
---

*make sure mininet, xterm and pox are installed on your linux

1. command: gcc 455_proj4.c
2. open 3 terminals
3. terminal 1   -> command: sudo mn -c
4. terminal 2   -> command: cd pox/
5.              -> command: ./pox.py log.level --DEBUG misc.proj4_455
6. terminal 1   -> command: sudo mn --mac --switch ovsk --controller remote
7.              -> check if it displays 'INFO:openflow.of_01... connected
8.              -> make sure there is a word 'connected'
9.              -> command: h2 ./a.out Recv h2-eth0 output.txt &
10.             -> command: h1 ./a.out Send h1-eth0 10.0.0.2 tux.txt
11. terminal 3  -> command: diff tux.txt output.txt 
12.             -> THE RESULT SHOULD BE EMPTY (meaning both files have same content)

*note 1: change interface, h2 ip address and, filename accordingly.