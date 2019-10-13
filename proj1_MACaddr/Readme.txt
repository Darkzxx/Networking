Instruction on building and compiling
--------------------------------------

1. download 455_proj2.c file into your linux
2. command: gcc 455_proj2.c
3. command: sudo mn
4. on mininet terminal command: xterm h1 
5. on mininet terminal command: xterm h2
6. on mininet look for ether address in command: h2 ifconfig -a
7. on Node:h2 terminal, command: ./a.out Recv h2-eth0
8. on Node:h1 terminal, command: ./a.out Send h1-eth0 <h2_ether_address> 'data'

example: 
./a.out h1-eth0 12:34:56:78:90:ab 'This is a test'

*note 1: type in h2_ether_address without the <> brackets 
*note 2: type any string in the data but also include ' before and after string
