Instruction on building and compiling
-------------------------------------

*make sure mininet and xterm are install on your linux
*wireshark is optional to see the ARP packet

1. download 455_proj2.c into your linux
2. command: gcc 455_proj2.c
3. command: sudo mn
4. on mininet terminal command: xterm h1
5. on mininet terminal command: h2 ifconfig -a
6. look for h2 IP address
7. on Node:h1 terminal, command: ./a.out h1-eth0 <h2_IP_address>

example:
./a.out h1-eth0 10.0.0.2

*note 1: h1-eth0 is an interface for Node:h1, if you wanna know your node interface use 'ifconfig -a' command