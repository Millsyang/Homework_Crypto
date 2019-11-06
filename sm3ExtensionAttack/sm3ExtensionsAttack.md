# SM3长度扩展攻击
1901210741 杨洲
密码学第一次编程作业 2019.10.16
运用python gmssl库实现长度扩展攻击

func.py 定义了一系列常用的函数,
sm3.py 定义了sm3 hash函数,
sm3lea.py 包含了sm3长度扩展攻击的实现和扩充消息的函数。

设计思路：
1.设定一个密钥，随机输入一串消息‘message’，计算出hash值，记为oldhash
2.构造一个消息，在不知道密钥具体内容，只知道密钥长度和oldhash的情况下，推断出该消息的hash值，
    记为guesshash
3.重新计算构造出的消息的hash值，记为newhash，比较guesshash和newhash，若结果相同，则攻击成功。

具体攻击细节：
在只知道密钥长度的情况下，随便用一串等长的消息（记为‘s*’）代替密钥，然后按照原hash函数的填充方法填充‘s*’+‘message’，在填充后的消息上附加一串消息m'，再次按hash函数的填充方法进行填充，将
oldhash转化为初始向量，对附加的消息加密，即可得到合法的hash值。

原理：无论知不知道secret的具体内容，只要长度不变，附加的消息串及其填充内容是不变的，所以可以用
正确的消息得到的oldhash直接作为中间向量对后面的消息进行加密，从而得到构造消息的合法hash值。

实验结果:
![Image text](https://github.com/Millsyang/sm3-Length-extension-attack/blob/master/demo.png)
