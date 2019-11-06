from gmssl import func,sm3
import random

#将hash值转化为中间变量
hash2v_mid = lambda hash:[int(hash[i*8:(i+1)*8],16)for i in range(8)]

#用于攻击的函数
def sm3_Len_Extension_Attack(msg,sec_len,oldhash,append_m):
    """
    msg:原来的消息
    sec_len:密钥长度
    oldhash：原来的hash值
    append_m:附加消息
    """
    new_secret = 'A' * secret_len
    #构造虚假消息
    exmsg = my_padding(func.bytes_to_list(bytes(new_secret + msg.__str__(), encoding='utf-8')))
    mid = round(len(exmsg) / 64)    #原来的消息+padding的分组数
    exmsg += func.bytes_to_list(bytes(append_m, encoding='utf-8'))
    exmsg = my_padding(exmsg)
    end = round(len(exmsg) / 64)  #虚假消息的分组数

    #只解出附加消息计算
    B = []
    for i in range(mid, end):
        B.append(exmsg[i * 64:(i + 1) * 64])

    #将oldhash转化为附加消息的初始向量并重新计算hash值
    V = []
    v_mid = hash2v_mid(oldhash)
    V.append(v_mid)
    for i in range(0, end - mid):
        V.append(sm3.sm3_cf(V[i], B[i]))
    y = V[i + 1]
    result = ""
    for i in y:
        result = '%s%08x' % (result, i)
    return result

#用于填充消息的函数
def my_padding(msg):
    len1 = len(msg)
    reserve1 = len1 % 64
    msg.append(0x80)
    reserve1 = reserve1 + 1
    range_end = 56
    if reserve1 > range_end:
        range_end = range_end + 64

    for i in range(reserve1, range_end):
        msg.append(0x00)

    bit_length = len1 * 8
    bit_length_str = [bit_length % 0x100]
    for i in range(7):
        bit_length = int(bit_length / 0x100)
        bit_length_str.append(bit_length % 0x100)
    for i in range(8):
        msg.append(bit_length_str[7 - i])
    return msg


#密钥
secret = '1901210741'
secret_len = len(secret)
msg = input('Enter you message:')
old_hash = sm3.sm3_hash(func.bytes_to_list(bytes(secret + msg.__str__(),encoding='utf-8')))
print('hash of \''+msg+'\' : '+old_hash)

#message want to add
append_m = 'Length extension attack'
new_msg_i = my_padding(func.bytes_to_list(bytes(secret + msg.__str__(),encoding='utf-8'))) \
          + func.bytes_to_list(bytes(append_m,encoding='utf-8'))


new_hash = sm3.sm3_hash(list(new_msg_i))
print('Create a deceptive message.(\'A*\'+msg+padding+m\')')
print('Appended message is : ' + str(func.list_to_bytes(new_msg_i)))

print('We guess its hash is : '+sm3_Len_Extension_Attack(msg,secret_len,old_hash,append_m))
print('And factually its hash is : '+new_hash)
if new_hash == sm3_Len_Extension_Attack(msg,secret_len,old_hash,append_m):
    print('Success!')
else:
    print('Failure!')
