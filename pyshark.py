
import pyshark
import json
from pyshark.capture.capture import Capture
import matplotlib.pyplot as plt
sum = 0 

capture  = pyshark.LiveCapture(interface='lo', bpf_filter='port 4040')
capture2 = pyshark.LiveCapture(interface='lo', display_filter='tcp.analysis.fast_retransmission')
capture.sniff(timeout=30)
retransmition  =0 

x = 0 
for i in range(0 , len(capture)):
    if 'retransmission' in str(capture[i]):
        retransmition += 1

file = open('/home/kabir/file.json','r')
jsonstring = file.read()
file.close()
dic = json.loads(jsonstring)
if 'udp' in str(dic['end']['streams'][0]):
    print(' sender troughput : ' , dic['end']['streams'][0]['udp']['bits_per_second'])
else : 
    print(' sender troughput : ' , dic['end']['streams'][0]['sender']['bits_per_second'])


print('number of packets : ' , len(capture))
print(' number of retransmiton tcp packets : ', retransmition)
plot_x = []
plot_y = []

for i in dic['intervals']:
    
    bitps = i ['streams'][0]['bits_per_second'] 
    time = i ['streams'][0]['end']
    plot_y.append(bitps)
    plot_x.append(time)

plt.subplot(1, 2, 1)    
plt.plot(plot_x, plot_y)

file2 = open('/home/kabir/server.json','r')
jsonstring = file2.read()
file2.close()

dic = json.loads(jsonstring)
plot_xx = []
plot_yy = []

for i in dic['intervals']:
    bitps = i ['streams'][0]['bits_per_second'] 
    time = i ['streams'][0]['end']
    plot_yy.append(bitps)
    plot_xx.append(time)

plt.subplot(1, 2, 2)    
plt.plot(plot_xx, plot_yy)
plt.show()