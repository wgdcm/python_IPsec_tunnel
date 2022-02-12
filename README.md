## Python IPsec Tunnel

This python program acts as a simple tunnel between two hosts. In this tunneling program, we use the IPsec protocol instead of the IP protocol. Due to the IPsec protocol, this program provides data encryption, authentication, and replay protection.

### Requirements 
-2 Linux operating system hosts.

-Install Python3.

    sudo apt-get update
    sudo apt-get install python3.6
    
-Install PyCrypto.
    
    sudo apt-get -y install python3-pip
    sudo pip install pycrypto
    
### Setup

In the first computer, run following commands to setup a tunnel interface called asa0,

    sudo ip tuntap add dev asa0 mode tun
    sudo ip addr add 10.0.1.1/24 dev asa0
    sudo ip link set dev asa0 up

In the second computer, run following commands to setup a tunnel interface called asa1,

    sudo ip tuntap add dev asa1 mode tun
    sudo ip addr add 10.0.1.2/24 dev asa1
    sudo ip link set dev asa1 up

Assign any IP address to the interfaces. (You can also change the tunnel interface and IP addresses as needed.)

### How to run

Run this command in a Linux environment. ( You can run the same program on both sides.)

    sudo python3 ipsectun.py
    
You will be asked what is the destination IP address on the destination PC.

Provide the correct destination PC IP address for the program.

You will be asked what is the interface name of your host and the name of the tunnel interface.

Provide the correct interface names for the program.

Do the same process for the other host.

### Note

You can use the ping utility to check the connection between two tunnel interfaces.
    
    ping -I 10.0.1.1 10.0.1.2

You can use any IP address for the interface. Source pc IP address is automatically received by the program and you can enter the original IP address when the program starts.

This program uses the IPsec ESP header with encryption and authentication.
