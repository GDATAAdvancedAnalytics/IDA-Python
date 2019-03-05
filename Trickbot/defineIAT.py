#
# This script has been written for the Trickbot sample with sha256 8F590AC32A7C7C0DDFBFA7A70E33EC0EE6EB8D88846DEFBDA6144FADCC23663A
# Tested with IDA 6.9 and IDA 7.1
#

from idaapi import *
import idautils

g_stringArrayStart = 0x00427C1C #beginning of the array of pointers to the base64 encoded strings
keyAddress = 0x0042A050 #address of the base64 alphabet
g_key = list(GetString(Dword(keyAddress), -1, ASCSTR_C)) # e.g. 'azcNwZVEXQybv2s6Lg9tjkxOr4uMKA1SWJHoBqTm/f0Fn8peCI7hiU5GRd+YD3Pl'

g_ImportStructBase = 0x0042A058 #Import Table of the runtime genereated Import Address Table (IAT)
g_IATptr = 0x0042A648 #address of where the pointer to the IAT is stored. Used as base when referencing the IAT

class crypt:
  def __getDWORD(self, instr):
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
      print "[-] Error: input in \"__unscramble\" is garbage"
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

def getStringFromPointer(offset):
  addr = g_stringArrayStart + (offset * 4)
  return GetString(Dword(addr), -1, ASCSTR_C)


def getIATasList():
  """
  Take information at g_ImportStructBase, apply reverse engineered structure on it to get all import names
  return list of IAT entries in their order
  """
  base = g_ImportStructBase
  cryptHelper = crypt()
  
  IAT = [0 for i in range(130)] # c++: new(0x208u) bytes;
  for i in range(8): #8 elements in array
    dllNameOffset =  Dword(base)
    funcNameArrayStart =  Dword(base + 4)
    funcNameArrayEnd =  Dword(base + 8)
    IATOffset =  Dword(base + 12) / 4 #IAT during runtime dynmically on heap
    
    for ii in range(funcNameArrayStart, funcNameArrayEnd + 1): #check in code is ">=", not ">", so the end is +1
      st = getStringFromPointer(ii)
      dec = cryptHelper.decrypt(st)
      IAT[IATOffset] = dec.replace('\x00',"") #remove zero byte padding from strings
      IATOffset += 1
    base += 16
  return IAT

def setIATasLocalType(IATlist):  
  """  
  Create one huge IAT structure, import it as Local Type and set the type to g_IATptr
  """  
  funcDefinition = "struct IAT {"  
  for IATentry in IATlist:
    if IATentry != 0:
      funcDefinition +=  "%s *%s;" % (IATentry, IATentry)
  funcDefinition += "};"

  if SetLocalType(-1, funcDefinition, 0) == 0:
    print "[-] Error setting IAT as local type"
    return
  
  if not SetType(g_IATptr, "IAT* IAT;"):
    print "[-] Error when setting IAT type"


def traceUsage(addr, register, steps):
  """
  Given a start address, a register which holds a value and the number of steps,
  this function disassembles forward #steps instructions and traces the value of <register>
  until it is used in a call instruction. It then returns the offset added to <register> and the address of the call
  Note that this tracing is very basic and does neither handle multiple registers at the same time nor any other modification than adding constants
  e.g.:
  00401622 mov eax, g_IAT           //start at addr = 0x00401622, register = "eax"
  00401627 mov ecx, [eax+0Ch]       //trace ecx, forget eax from now on. Save offset "0x0C"
  0040162A push    edx              //ignore
  0040162B call ecx                 //return offset 0x0c and address 0x0040162B
  """
  potentialOffset = -1
  localRegister = register

  for step in range(steps):
    addr = NextHead(addr)
    dis = GetMnem(addr)

    if dis == 'mov' and localRegister in GetOpnd(addr,1): #look for e.g."mov eax, [<register>+1CCh]"
      potentialOffset = GetOpnd(addr,1)
      if potentialOffset[0] != '[' or potentialOffset[-1] != ']': #"[<register>+1CCh]"
        continue
      potentialOffset = potentialOffset[1:-1] #"<register>+1CCh"

      if '+' in potentialOffset: #we might have had "mov ecx, [eax]", so there is no plus
        potentialOffset = potentialOffset.split(register+'+')[1] # "1CCh"
      else:
        potentialOffset = "0"

      if potentialOffset.endswith('h'):
        potentialOffset = int(potentialOffset[:-1], 16) / 4 #"1cc"
      else:
        potentialOffset = int(potentialOffset) / 4

      localRegister = GetOpnd(addr,0) #get new register to search for upcoming call-instruction    

    elif dis == 'call' and GetOpnd(addr,0) == localRegister:
      return potentialOffset, addr
  
  if potentialOffset != -1:
    print "[-] Error: Got potentialOffset %s but no corresponding call - maybe increase the steps range?" % (str(potentialOffset))
  return -1, -1 #errör

def helper_getTinfoOfFuncName(funcName):
  """
  Return the tinfo-object for a given function name
  Success/Fail is transported via second return value
  """
  sym = idaapi.til_symbol_t()
  sym.til = idaapi.cvar.idati
  sym.name = funcName
  tinfo = idaapi.tinfo_t()

  namedType = idaapi.get_named_type(sym.til, sym.name, 0)

  if namedType == None:
    print '[-] Error: Could not find %s' % (sym.name)
    return tinfo, False
    
  tinfo.deserialize(sym.til, namedType[1], namedType[2])

  return tinfo, True

def helper_getFunctionDefinitionString(funcName):
  """
  Return function definition of funcName as string. Empty string on error
  e.g. helper_getFunctionDefinitionString("SetCurrentDirectoryW")
  returns "typedef BOOL __stdcall SetCurrentDirectoryW(LPCWSTR lpPathName);"
  """
  tinfo, success = helper_getTinfoOfFuncName(funcName)
  if not success:
    print "[-] Error: Cannot find tinfo for function name %s" % (funcName)
    return ""
    
  #cast tinfo to string in order to parse it
  funcStr = tinfo.__str__()
  funcStr = funcStr.split('(')
  funcStr = "typedef " + funcStr[0] + " " + funcName + " (" + funcStr[1] + ";"
  return funcStr

def importAllFunctionDefinitionsAsLocalType(IATlist):
  """
  This function iterates over all entries of IATlist and creates and imports the function definitions for later use when creating the IAT structure.  
  e.g.: Before you can create a function pointer structure with "SetCurrentDirectoryW *SetCurrentDirectoryW;"
  you need to define "typedef BOOL __stdcall SetCurrentDirectoryW(LPCWSTR lpPathName);" first.
  """
  for funcStr in IATlist:
    funcDefinition = helper_getFunctionDefinitionString(funcStr)
    
    if funcDefinition == "":
      print "[-] Error: Cannot get function definition for function name %s" % (funcStr)
      continue
  
    if SetLocalType(-1, funcDefinition, 0) == 0:
      print "[-] Error when setting local type %s. Does it already exist?" % (funcStr)


def setFunctionInformation(funcName, callAddress):
  """
  This function takes the function index offset for the IAT and the address, where the call to the IAT is made.
  It tells IDA to define the correct definition to the call, including local variables and comments for the disassembler and the decompiler
  """  
  tinfo, success = helper_getTinfoOfFuncName(funcName)
  if not success:
    print "[-] Error: Cannot find tinfo for function name %s" % (funcName)
    return False

  errorCode = idaapi.apply_callee_tinfo(callAddress, tinfo) #in IDA 6.9 this returns <type 'NoneType'>, in IDA 7.1 it is "True"
  success = idaapi.set_op_tinfo2(callAddress, 0, tinfo)
  if errorCode not in [None, True] or not success:
    print "[-] Error when setting function information for %s at %s" % (callAddress, hex(int(callAddress)))
    return False
  return True


def importTypeLibraries():
  """
  Import type libraries needed for function definitions
  """  
  if add_til("wdk8_um") != 1 or add_til("mssdk_win7") != 1:
    return False
  return True


if __name__ == "__main__":
  #ensure that all needed type libaries are loaded
  if not importTypeLibraries():
    print "[-] Error importing type libaries"
    raise Exception("Type lib import failed")

  IATlist = getIATasList()  
  
  importAllFunctionDefinitionsAsLocalType(IATlist)
  
  setIATasLocalType(IATlist)

  #propagate type information for each address where the IAT is used
  for i in idautils.XrefsTo(g_IATptr,0):
    addr = i.frm
    dis = GetMnem(addr)
    if not 'mov' == dis:
      print "[-] Crap, no mov at %s" % (hex(int(addr)))
      continue
    
    offset, addrOfCall = traceUsage(addr, GetOpnd(addr, 0), 18)
    if offset == -1 or addrOfCall == -1:
      print "[-] Error: Trace unsuccessful at %s" % (hex(int(addr)))
    else:
      funcName = IATlist[offset]
      if not setFunctionInformation(funcName, addrOfCall):
        print "[-] Error with offset %s at %s with call on %s" % (str(offset), hex(int(addr)), hex(int(addrOfCall)))
      else:
        print "[+] Success with offset %s at %s with call on %s" % (str(offset), hex(int(addr)), hex(int(addrOfCall)))