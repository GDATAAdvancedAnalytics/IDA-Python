#
# This script has been written for the Trickbot sample with sha256 8F590AC32A7C7C0DDFBFA7A70E33EC0EE6EB8D88846DEFBDA6144FADCC23663A
# Tested with IDA 6.9
#

import idautils

g_stringArrayStart = 0x00427C1C
keyAddress = 0x0042A050

#key from binary (first element of blob)
g_key = list(GetString(Dword(keyAddress), -1, ASCSTR_C)) # == 'azcNwZVEXQybv2s6Lg9tjkxOr4uMKA1SWJHoBqTm/f0Fn8peCI7hiU5GRd+YD3Pl'

class crypt:
    def __getDWORD(self, instr):
        global g_key
        res = []

        for el in instr:
            for i in range(len(g_key)):
                if el == g_key[i]:
                    res.append(i)
                    break

        while len(res) < 4: res.append(0) #pad DWORD with zeros
        return res
        
    def __unscramble(self, instr):
        if len(instr) != 4:
            print "[-]Error, input in \"unscramble\" is garbage"
            return ""

        a0 = (4 * instr[0] + ((instr[1] >> 4) & 3)) & 0xff
        a1 =  (16 * instr[1] ^ (instr[2] >> 2) & 0xF) &0xff
        a2 =  (instr[3] + (instr[2] << 6)) &0xff
        return "".join([chr(a0), chr(a1), chr(a2)])


    def decrypt(self, inputString):
        res = ""
        #unscramble string in blocks of 4 bytes
        for i in range(0, len(inputString),4):
            base64Foo = self.__getDWORD(inputString[i:i+4])
            res += self.__unscramble(base64Foo)
        return res


def getOperandBackwards(addr, maxrange=5):
    """
    Disassemble backwards from <addr> up to <maxrange> instructions
    Search for a "push <const>" instruction and return the pushed value
    """
    ret = -1
    for i in range(maxrange):
        addr = PrevHead(addr)
        dis = GetMnem(addr)

        if dis == "push":
            operand = GetOpnd(addr, 0)
            if operand.endswith('h'):
                ret = int(operand[:-1], 16) #cut off 'h' at the end, then convert to int from hex
                break
            elif operand.isdigit():
                ret = int(operand, 10)
                break
    return ret

def getStringFromPointer(offset):
    global g_stringArrayStart
    addr = g_stringArrayStart + (offset * 4)
    return GetString(Dword(addr), -1, ASCSTR_C)

def printIAT():
    base = 0x0042A058
    cryptHelper = crypt()
    IAT = [0 for i in range(0x208)] # c++: new(0x208u);
    for i in range(8): #8 elements in array
        dllNameOffset =  Dword(base)
        funcNameArrayStart =  Dword(base + 4)
        funcNameArrayEnd =  Dword(base + 8)
        IATOffset =  Dword(base + 12) / 4 #IAT during runtime dynmically on heap
    
        #print DLL name
        st = getStringFromPointer(dllNameOffset)
        print hex(int(base)), dllNameOffset, st, cryptHelper.decrypt(st)

        #print imported function names
        for ii in range(funcNameArrayStart, funcNameArrayEnd + 1): #check in code is ">=", not ">", so the end is +1
            st = getStringFromPointer(ii)
            dec = cryptHelper.decrypt(st)
            if IAT[IATOffset] != 0: print "AAAA",IATOffset #TODO proper error handling
            IAT[IATOffset] = dec.replace('\x00',"") #remove zero byte padding from strings
            IATOffset += 1
            print ii, st, dec
        base += 16
    
    print "----------------"
    print "struct IAT {"
    for i in range(len(IAT)):
        if IAT[i] != 0:
            print "%s *%s;" % (IAT[i], IAT[i])
    print "}"

def setCommentToDecompilation(comment, address):
    #Works in IDA 6.9 - May not work in IDA 7
    #see https://www.hex-rays.com/products/decompiler/manual/sdk/hexrays_8hpp_source.shtml used structures, const and functions
    cfunc = idaapi.decompile(address)
    
    #get the line of the decompilation for this address
    eamap = cfunc.get_eamap()
    decompObjAddr = eamap[address][0].ea

    #get a ctree location object to place a comment there
    tl = idaapi.treeloc_t()
    tl.ea = decompObjAddr
    
    commentSet = False
    #since the public documentation on IDAs APIs is crap and I don't know any other way, we have to brute force the item preciser
    #we do this by setting the comments with different idaapi.ITP_* types until our comment does not create an orphaned comment
    for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
        tl.itp = itp    
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        #apparently you have to cast cfunc to a string, to make it update itself
        unused = cfunc.__str__()
        if not cfunc.has_orphan_cmts():
            commentSet = True
            cfunc.save_user_cmts()
            break
        cfunc.del_orphan_cmts()

    if not commentSet:
        print "[ERROR] Please set \"%s\" to line %s manually" % (comment, hex(int(address)))


def decryptAllReferencesToCryptFunction(cryptFunctionAddress):
    cryptHelper = crypt()
    for addr in idautils.CodeRefsTo(cryptFunctionAddress,0):
        #find pushes from xrefs backwards to get the function's argument
        offset = getOperandBackwards(addr, 10)
        if offset == -1:
            print "[-] Error at %s - did not find correct byte" % hex(int(addr))
        else:
            strFromPtr = getStringFromPointer(offset)
            decryptedString = cryptHelper.decrypt(strFromPtr)
            setCommentToDecompilation(decryptedString, addr)
            print "[+] Decrypted string at Addr: %s Offset: %s Crypted: %s Decrypted: %s" % (hex(int(addr)), offset, strFromPtr, decryptedString)

if __name__ == "__main__":
    decryptAllReferencesToCryptFunction(0x00405210)
    print "----------------"

    decryptAllReferencesToCryptFunction(0x004019F0)
    print "----------------"

    decryptAllReferencesToCryptFunction(0x00407110)
    print "----------------"

    #get check IPs and domains to check
    base = 0x00425358
    cryptHelper = crypt()
    while True:    
        offset =  Dword(base)
        if offset == 0:
            break    
        strFromPtr = getStringFromPointer(offset)
        print "[+] Decrypted string at Addr: %s Offset: %s Crypted: %s Decrypted: %s" % (hex(int(base)), offset, strFromPtr, cryptHelper.decrypt(strFromPtr))
        base += 4
    print "----------------"

    #get paths for checking IPs and domains
    base = 0x0042538C
    for i in range(0x0042538C, 0x004253B8, 4):    
        offset =  Dword(i)
        if offset == 0:
            continue    
        strFromPtr = getStringFromPointer(offset)    
        print "[+] Decrypted string at Addr: %s Offset: %s Crypted: %s Decrypted: %s" % (hex(int(i)), offset, strFromPtr, cryptHelper.decrypt(strFromPtr))
    print "----------------"

