# pbproxy
The Plugboard proxy  adds an extra layer of encryption to connections towards TCP services. Instead of connecting directly to the service, clients connect to pbproxy (running on the same
server), which then relays all traffic to the actual service. The service is restricted to only listen on local interface, making it inaccessible from public network.
Before relaying the traffic, pbproxy *always* decrypts it using a static symmetric key. Since the TCP service is only connected through the proxy instance to the client, which is in turn encrypted end-to-end using a private key, the service is secure towards any zero day intrusions.

### To run:
```
Ensure you have openssl library installed. The library is required to use AES in CTR mode.
sudo apt-get install libssl libssl-dev

git clone https://github.com/bhaveshgoyal/pbproxy.git
cd pbproxy/
make
chmod +x ./pbproxy
./pbproxy [-l port] -k keyfile <TCPserviceIP> <TCPservicePort>

```
  -l  Reverse-proxy mode: listen for inbound connections on <port> and relay
      them to <TCPserviceIP>:<TCPservicePort>

  -k  Use the symmetric key contained in <keyfile> (as a hexadecimal string)



To test the proxy on your local SSH daemon, let's see how the program could be used to harden an
SSH server. Assume that we want to protect a publicly accessible sshd running
on vulnerable.my.ip. First, we configure sshd to listen *only* on the
localhost interface, making it inaccessible from the public network. Then, we
fire up a reverse pbproxy instance on the same host:

  pbproxy -k mykeyfile -l 2222 localhost 22

Now, a client can then connect to the SSH server using the following command:

  ssh -o "ProxyCommand pbproxy -k mykeyfile vulnerable.my.ip 2222" username@localhost

Here, username is the the value of `$USER` for the public service, who the clients wants to login as.

----------------------------------
**A Brief Note on implementation:**

The program makes use of builtin function getopt to parse the optional command line arguments given as input by the user.

The arguments are stored and validated using the return values provided by calls to File I/O and openssl/aes modules. This allows the program to invalidate any
objectionable user input and handle the corresponding errors.

The program then checks if it is loaded in forward or reverse proxy mode. If the flag -l is not set, it operates in the forward proxy mode, multiplexing between STDIN and the corresponding reverse proxy connection to forward input from STDIN to reverse proxy server and receive the traffic from the server to STDOUT. The output is decrypted each time before the data is forwarded to STDOUT and encrypted before sending the data towards the reverse proxy server operating. Additional checks have been introduced to observe if the reverse proxy server has sent an EOF message, in which case the forward proxy closes its end of connection using shutdown function and just read any other incoming data from the server. Moreover, a new IV is generated each time using RAND\_bytes to make sure that any of the IVs are not reused. The generated IV is transmitted to the server as the first 8 bytes in the encrypted message. Since this is implemented as a protocol basis, the server knows to always extract the initial bytes from the encrypted text to use as an IV for decrypting the rest bytes of ciphertext. All buffer declarations are dynamic and free'd before returning from any call to lighten the work of garbage collector ;)

If the program is used is reverse proxy mode (-l flag specified), the server multiplexes between the forward proxy and TCP service. The incoming and outgoing connections are handled by a module called forw\_handler which is a common stub to both the tcp service and forward proxy connections. The stub differentiates between the connections using flags, which are additionally passed using an argument struct to the function. It was observed that the TCP at lower layers would combine two packets in case they were not taken out of the receive buffer after they were processed. This was observed to happen as a delay in flushign the output to STDOUT while decrypting the message at the same time. To handled the case, an additional delay was added to subsequent write calls to the forward service using using POSIX specified usleep command. This ensured that subsequent packets had enough time to get processed before another could comein and get merged to it. If we did not handle this case, SSH service would abruptly crash with bad packet length message which happened due to the same TCP's packet merger mechanism.

-----------------------------------
*Production Environment*

```
gcc specifications:
Configured with: --prefix=/Library/Developer/CommandLineTools/usr --with-gxx-include-dir=/usr/include/c++/4.2.1
Apple LLVM version 9.0.0 (clang-900.0.38)
Target: x86_64-apple-darwin17.0.0

OS specifications:
Darwin 17.0.0 x86_64
(macOS High Sierra)

```
Code Reference Credits:

StackOverflow:
AES Operation in CTR Mode: https://stackoverflow.com/questions/3141860/aes-ctr-256-encryption-mode-of-operation-on-openssl
