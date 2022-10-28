
import dpkt
import socket

class TCPFlow:
    # init constructor
    def __init__(self, flownum, sip, sport, dip, dport, starttime):
        self.flowNum = flownum
        self.sIp = sip
        self.sPort = sport
        self.dIp = dip
        self.dPort = dport
        self.startTime = starttime
        self.setUpCount = 1
        self.endTime = 0
        self.numBytes = 0
        self.transactionCount = 0
        self.transactionList = []
        self.ackTransList = []
        self.ackTransCount = 0
        self.winScale = 0
        self.winScaleSet = False

        self.cwndList = []
        self.ssthresh = 0
        self.fastRetransmissionNum = 0
        self.RetransmissionNum = 0
        self.slowStartTotal = 0
        self.slowStart = False
        self.prevAck = 0  # assuming that the src port is 80 (not this sPort value)
        self.totalSameCurrAck = 1

        self.currCwind = 0
    # incrememnt the slow start variable (time out)
    def incSlowStart(self):
        self.slowStartTotal += 1
    # get the cwnd information for printing
    def getCwndInfo(self):
        return self.cwndList, self.fastRetransmissionNum, self.RetransmissionNum, self.slowStartTotal
    # resets the curr ack count after a retransmission
    def resetCurrAckCount(self):
        self.totalSameCurrAck = 1
    # increments regular retransmission number (both triple ack and time out)
    def incRetrans(self):
        self.RetransmissionNum += 1
    # increments the fast retrans num (triple ack)
    def incFastRetrans(self):
        self.fastRetransmissionNum += 1
    # there was a retransmission
    def retrans(self, isTriple):
        self.ssthresh = self.currCwind/2
        self.cwndList.append(self.currCwind)
        if isTriple:
            self.currCwind /= 2
            self.slowStart = False
        else:
            self.currCwind = 1
            self.slowStart = True
    # incr cwind based on some criteria
    def incCwind(self):
        if not self.ssthresh == 0 and self.currCwind >= self.ssthresh:
            self.slowStart = False
        if self.slowStart:
            self.currCwind *= 2
        else:
            self.currCwind += 1

    def getAckInformation(self):
        return self.prevAck, self.totalSameCurrAck
    def setPreviousAck(self, ack):
        self.prevAck = ack

    def getWinScale(self):
        return self.winScale
    def setWinScale(self, winScale):
        self.winScale = winScale
    def incrAckCount(self):
        self.totalSameCurrAck+=1
    def appendAckTrans(self, newTransaction):
        self.ackTransList.append(newTransaction)
    def getAckTransactionInfo(self):
        return self.ackTransCount, self.ackTransList
    def appendTransaction(self, newTransaction):
        self.transactionList.append(newTransaction)
    # gets the transaction information
    def getTransactionInfo(self):
        return self.transactionCount, self.transactionList
    # increments the transaction count
    def incTransactionCount(self):
        self.transactionCount += 1
    # adds bytes to the number of bytes for throughput calculation
    def addBytes(self, bytes):
        self.numBytes += bytes
    # sets the end time stamp
    def setEnd(self, endtime):
        self.endTime = endtime
    # gets the setUpCount
    def getSetUpCount(self):
        return self.setUpCount
    def incSetUpCount(self):
        self.setUpCount += 1
    # gets the ports
    def getPorts(self):
        return self.sPort, self.dPort
    #gets the variables
    def getElements(self):
        return self.flowNum, self.sIp, self.sPort, self.dIp, self.dPort
    def calculateThroughput(self):
        return self.numBytes / (self.endTime- self.startTime )


# gets the string of the input ip addr
def getIpStr(addr):
    return socket.inet_ntop(socket.AF_INET, addr)

# checks if the flow list has these ports already
def doesNotContains(flowList, sPort, dPort):
    for j in range(len(flowList)):
        _, _, flowSPort, _, flowDPort = flowList[j].getElements()
        if (flowSPort == sPort and flowDPort == dPort) or (flowSPort == dPort and flowDPort == sPort):
            return False
    return True

# gets the index in flow list that has these ports
def getFlowListIndex(flowList, sPort, dPort):
    for j in range(len(flowList)):
        _, _, flowSPort, _, flowDPort = flowList[j].getElements()
        if (flowSPort == sPort and flowDPort == dPort) or (flowSPort == dPort and flowDPort == sPort):
            return j
    return -1
# checks if the list already contains the transaction
def alreadyContainTransaction(transactionList, transaction):
    for j in range(len(transactionList)):
        currentTransaction = transactionList[j]
        if currentTransaction["SEQ"] == transaction["SEQ"] and currentTransaction["ACK"] == transaction["ACK"] and currentTransaction["WIN"] == transaction["WIN"]:
            return True
# finds the index of the Window Scale
def findWScaleIndex(tupleList):
    for i in range(len(tupleList)):
        tuple = tupleList[i]
        if tuple[0] == 3:
            return i

ACK = 16
FIN = 1
SYN = 2

flowList = []  # the list containing all flows
# s = "assignment2.pcap"  # need to comment this out
s = input("Enter the file name in the form of NAME.pcap: ")
f = open(s, 'rb')
pcap = dpkt.pcap.Reader(f)
countOfFlows = 1
# for parsing
for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    # if it is the FIN flag then set the end time stamp
    if tcp.flags & FIN == FIN:
        newFlow = TCPFlow(countOfFlows, ip.src, tcp.sport, ip.dst, tcp.dport, ts)
        flowSPort,flowDPort = newFlow.getPorts()
        index = getFlowListIndex(flowList, flowSPort, flowDPort)
        flowList[index].setEnd(ts)

    # if it has the SYN flag then create a new flow object and append it to the list
    if tcp.flags & SYN == SYN:
        tupleList = dpkt.tcp.parse_opts(tcp.opts)
        winIndex = findWScaleIndex(tupleList)
        # print(int.from_bytes(tupleList[winIndex][1], "little"))
        newFlow = TCPFlow(countOfFlows, ip.src, tcp.sport, ip.dst, tcp.dport, ts)
        newFlow.setWinScale(int.from_bytes(tupleList[winIndex][1], "little"))
        # print(newFlow.getWinScale())
        flowSPort,flowDPort = newFlow.getPorts()
        if doesNotContains(flowList, flowSPort, flowDPort): # if the flow list doesnt already have this flow then append it
            flowList.append(newFlow)
            countOfFlows += 1
        else:
            index = getFlowListIndex(flowList, flowSPort, flowDPort)
            currentFlow = flowList[index]
            setUpC = currentFlow.getSetUpCount()
            curSPort,curDPort = currentFlow.getPorts()
            if setUpC == 0:
                if curSPort == flowDPort and curDPort == flowSPort:
                    currentFlow.incSetUpCount()
        continue

    # if it has the ACK flag then do what is needed
    if tcp.flags & ACK == ACK:
        newFlow = TCPFlow(countOfFlows, ip.src, tcp.sport, ip.dst, tcp.dport, ts)
        flowSPort, flowDPort = newFlow.getPorts()
        index = getFlowListIndex(flowList, flowSPort, flowDPort)
        currentFlow = flowList[index]
        curSPort, curDPort = currentFlow.getPorts()
        previousAck, totalSameAck = currentFlow.getAckInformation()
        # checks acks for retransmission
        if curDPort == flowSPort: # if it is a packet sent from the reciever then check ack num
            if previousAck == 0:
                currentFlow.setPreviousAck(tcp.ack)
            else:
                if previousAck < tcp.ack: # it acknowledged the next set of bytes (piggybacked) reset everything
                    currentFlow.setPreviousAck(tcp.ack)
                    currentFlow.resetCurrAckCount()
                elif previousAck == tcp.ack:
                    currentFlow.incrAckCount()
        else: # it is from the sender and check ack to see if
            if not previousAck == 0:  # then there should be an ack
                if totalSameAck >= 3 and tcp.seq == previousAck:  # there is a tcp fast retransmission(triple ack)
                    currentFlow.incFastRetrans()
                    currentFlow.retrans(True)  # is triple ack
                elif tcp.seq == previousAck:  # there was a full retransmission (reset the cwnd back to 0)
                    currentFlow.incSlowStart()
                    currentFlow.retrans(False)  # is not a triple ack

        currentFlow.incCwind()



        if curSPort == flowSPort:
            currentFlow.addBytes(len(tcp.data)) # increment the number of bytes for throughput calculations

        # this is for getting the first two transactions
        transactionCount, transactions = currentFlow.getTransactionInfo()
        ackCount, ackTransactions = currentFlow.getAckTransactionInfo()
        transaction = {
            "SEQ": tcp.seq,
            "ACK": tcp.ack,
            "WIN": tcp.win
        }
        if ackCount < 2 and (not alreadyContainTransaction(ackTransactions, transaction)) and curDPort == flowSPort:
            currentFlow.incrAckCount()
            currentFlow.appendAckTrans(transaction)
            continue
        if transactionCount < 2 and not alreadyContainTransaction(transactions, transaction) and curSPort == flowSPort:
            currentFlow.incTransactionCount()
            currentFlow.appendTransaction(transaction)


# For displaying everything
# Printing the basic information
for i in range(len(flowList)):
    flowNum, sIp, sPort, dIp, dPort = flowList[i].getElements()
    setUpC = flowList[i].getSetUpCount()
    print(f'Flow {flowNum} | Source IP: {getIpStr(sIp)} | '
          f'Source Port: {sPort} | Dest IP: {getIpStr(dIp)} | '
          f'Dest Port: {dPort} | Throughput: {flowList[i].calculateThroughput()}')
print("\n")
# Printing the Transactions
for i in range(len(flowList)):
    _, transactions = flowList[i].getTransactionInfo()
    _, ackTransactions = flowList[i].getAckTransactionInfo()
    print(f'Flow {i+1} First 2 Transactions')
    for j in range(len(transactions)):
        print(f'Transaction {j+1}')
        print(f'Packet:   Sequence Number: {transactions[j]["SEQ"]} | Acknowledgement Number: {transactions[j]["ACK"]} | Window Size: {transactions[j]["WIN"]* 2 **flowList[i].getWinScale()}')
        print(f'Ack:      Sequence Number: {ackTransactions[j]["SEQ"]} | Acknowledgement Number: {ackTransactions[j]["ACK"]} | Window Size: {ackTransactions[j]["WIN"]* 2 **flowList[i].getWinScale()}')
    print("\n")

for i in range(len(flowList)):
    cwndList, fastRetransmissionNum, retransmissionNum, slowStart = flowList[i].getCwndInfo()
    List = []
    maxLen = len(cwndList)
    for j in range(3):
        if j == maxLen:
            break
        List.append(cwndList[j])
    # print(retransmissionNum)
    print(f'Flow {i+1} | First 3 Cwnds: {List} | Duplicate Acks: {fastRetransmissionNum} | Timeouts: {slowStart}')

f.close()
