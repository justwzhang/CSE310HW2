How to run code

Method 1 (Run in pycharm):
1. Open the project in the root folder
2. Make sure the dpkt package is installed properly
3. Run the program named analysis_pcap_tcp.py
4. You will be prompted to enter the name of the file (example is provided in the assignment 2 pictures.pdf)
    a.  the input format is important, to use the provided pcap filetype "assignment2.pcap" when prompted
5. Wait a little and the output should be in a similar format to the output provided in the pdf file

Method 2 (Run in cmd):
1. Open the cmd terminal and cd to the project directory
2. Make sure te dpkt package is installed
3. Run program with the source file being analysis_pcap_tcp.py
4. You will be prompted to enter the name of the file (example is provided in the assignment 2 pictures.pdf)
    a.  the input format is important, to use the provided pcap filetype "assignment2.pcap" when prompted
5. Wait a little and the output should be in a similar format to the output provided in the pdf file


Parts A and B explanations
Part A:
a) The source port, source IP, dest port, and dest IP are all obtained upon the first SYN flag detected
b) For the first two transactions I simply just get the packages for the first two sent by the sender then the next two sent back by the reciever
c) Each time the sender sends a packet I added up the tcp data length and saved the starting and ending time stamp. I then just did throughput = #packets / (end-start)

Part B:
a) I used tcp reno as the method of calculating the cwind.
    1) If a triple ack is detected then I halved cwind and ssthresh
    2) If a retransmission occurred without a triple ack then I halved ssthresh and reset cwind back to 1
b) I simply just added a counter that is incremented when either a triple ack or retransmission occurred without a triple ack